# -*- coding: utf-8 -*-
"""원격 Claude 위험 명령 막기(PreToolUse 훅). 원격 요청을 실행할 때만 remote_claude.py 가 --settings 로 붙인다.

- 막는 것: 배포·푸시, 원격 DB 쓰기, 폴더 통째 삭제, 시스템 설정 바꾸기, 내려받아 바로 실행, 비밀 값 읽기,
  이 보호 장치 자체(rc_guard·remote_claude.py·.claude/settings) 고치기, 프로젝트 밖 파일 쓰기.
- 막으면 종료 코드 2 + 이유(stderr) → Claude 는 그 도구를 못 쓰고 이유를 본다.
  막은 기록은 RC_GUARD_LOG 파일에 한 줄씩(JSON) 남기고, 다리가 사이트에 '위험 명령을 막았어요' 경고로 보낸다.
- 사이트에서 '위험 명령 허용'을 켜고 보낸 요청은 RC_ALLOW_DANGER=1 → 막지 않고 기록만 남긴다.
- 훅이 고장 나면(입력을 못 읽음·예외) 막는다(fail-closed). bypassPermissions 로 돌기 때문에 열어 두면 그대로 실행된다.
- 작업 폴더 제한(RC_DIRS, 2026-10-11): 다리가 사이트 설정 '작업 폴더'에서 고른 폴더(절대 경로 JSON 목록)를 넘겨주면
  그 밖은 읽기·쓰기·명령 모두 막는다. 이 제한은 '위험 허용'으로도 풀리지 않는다. RC_DIRS 가 없거나 '*' 이면 제한 없음.
- 한계: 글자 규칙이라 스크립트를 써서 실행하거나 python subprocess 로 돌리는 우회는 못 막는다. 보조 장치이고,
  최종 방어는 '위험 허용'을 함부로 켜지 않는 것 + 프로젝트 .claude/settings.json 의 deny 규칙이다.
"""
import fnmatch, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = (os.environ.get('RC_ROOT') or os.path.dirname(HERE)).lower()   # 다리가 작업 폴더를 넘겨줌(다른 사람 PC)
TEMP = os.environ.get('TEMP', '').lower()
PLANS = os.path.join(os.path.expanduser('~'), '.claude', 'plans').lower()
# 비밀 값이 든 폴더: 이 PC 의 study-helper(워커 키), 다른 사람 PC 의 다리 폴더(remote_claude.json)
SECRET_DIRS = [d.lower() for d in (os.path.join(ROOT, 'study-helper'), HERE if os.path.exists(os.path.join(HERE, 'remote_claude.json')) else '') if d]

CMD_RULES = [   # (이유, 정규식) — 명령 글자 전체에서 대소문자 무시로 찾는다
    # git 의 하위 명령 자리의 push 만(git -C 경로 push, git -c x=y push, git --git-dir=… push). 'git commit -m "fix push"' 는 통과
    ('배포·푸시', r'\bgit(\.exe)?(\s+-[Cc]\s+\S+|\s+--?[\w-]+(=\S*)?)*\s+push\b|deploy-(site|cf|gas)\.ps1|\brelease\.ps1|\bwrangler\b[^\n]*\b(deploy|publish|secret|delete|rollback)\b|\bclasp\s+(push|deploy|undeploy)|\bnpm\s+publish|\bgh\s+(repo\s+delete|release\s+(create|delete|upload|edit)|pr\s+merge)'),
    ('git 기록 지우기', r'\bgit\s+(reset\s+--hard|clean\s+-\w*f|branch\s+(?-i:-D)|checkout\s+--\s|restore\s+--source)'),
    ('원격 DB 쓰기', r'\bwrangler\b(?=[^\n]*--remote)(?=[^\n]*\bd1\b)(?=[^\n]*(\b(delete|drop|update|insert|alter|replace|create)\b|--file))'),
    ('폴더 통째 삭제', r'\b(Remove-Item|ri|rm|del|erase|rd|rmdir)\b[^\n;|&]*\s-r(e(c(u(r(se?)?)?)?)?)?(\s|$|:)|\brm\s+-\w*r|\b(rd|rmdir)\s+/s|\bdel\s+(/\w\s+)*/[sq]|\bformat\s+[a-z]:|\bshutil\.rmtree|\bClear-RecycleBin'),
    ('시스템 설정 바꾸기', r'\b(shutdown|Stop-Computer|Restart-Computer)\b|\breg(\.exe)?\s+(delete|add|import)\b|Set-ExecutionPolicy|\bschtasks\b[^\n]*/(create|delete|change)|\bsc(\.exe)?\s+(delete|config|stop)\b|\bnet\s+(user|localgroup)\b|\btakeown\b|\bicacls\b|\bSet-MpPreference\b|\bnetsh\b'),
    ('내려받아 바로 실행', r'\b(iwr|irm|Invoke-WebRequest|Invoke-RestMethod|curl|wget)\b[^\n|]*\|\s*(iex|Invoke-Expression|sh|bash|python|pwsh|powershell)\b|\bInvoke-Expression\b|\biex\b'),
    ('폴더 통째 삭제', r'\brm\b[^\n;|&]*\s(-\w*r\w*|--recursive)\b|\bfind\b[^\n;|&]*\s-delete\b|\brobocopy\b[^\n;|&]*\s/(mir|purge)\b'),
    ('원격 저장소 바꾸기', r'\bgit(\.exe)?\b[^\n;|&]*\bremote\s+(set-url|add|remove|rm)\b|\bgh\s+api\b[^\n]*(-X\s*|--method[\s=]+)(DELETE|PATCH|PUT)\b'),
    ('비밀 값 읽기', r'(^|[;&|(]\s*)(printenv|env|set)\s*($|[;&|)])|\b(Get-ChildItem|gci|dir|ls)\s+env:|\$env:\w*(KEY|TOKEN|SECRET|PASS)'),
    ('숨긴 명령 실행', r'\b(powershell|pwsh)(\.exe)?\b[^\n;|&]*\s-(e|ec|en|enc|enco\w*)\s+[A-Za-z0-9+/=]{16,}'),
    ('비밀 값 읽기', r'\bsync\.(j\w*|[*?]\S*)|study-helper[\\/][^\s"\']*[*?]|remote_claude\.(j\w*|[*?]\S*)|(^|[\s"\'\\/])\.env\b|\.dev\.vars|\bbridge\.json\b|dm-reply[\\/]profiles|\.credentials\.json|\bid_rsa\b|\.pem\b|ANTHROPIC_API_KEY|wrangler[^\n]*\bwhoami\b|\.wrangler[\\/]config'),
    ('보호 장치 고치기', r'\brc_gu|remote_claude\.(p\w*|[*?])|\.claude[\\/](settings|hooks)|auto-approve\.py'),
]
SECRET_PATH = re.compile(r'sync\.json$|[\\/]bridge\.json$|[\\/]dm-reply[\\/]profiles([\\/]|$)|[\\/]sync~\d|study-h~\d|remote~\d|remote_claude\.json$|\.dev\.vars$|\.env(\.|$)|\.credentials\.json$|id_rsa|\.pem$|\.key$|[\\/]\.wrangler[\\/]config', re.I)
# 보호 장치와, 나중에 묻지 않고 실행·적용되는 파일(훅·설정·자동 승인)은 고치지 못하게
SELF_PATH = re.compile(r'rc_guard\.py$|remote_claude\.py$|[\\/]\.claude[\\/](settings[^\\/]*\.json|hooks[\\/])|auto-approve\.py$', re.I)


def inside(full, base):
    """full 이 base 폴더 안인가(D:\\AI_HEO_evil 처럼 이름만 비슷한 폴더는 아님)."""
    try:
        return bool(base) and os.path.commonpath([os.path.realpath(full), os.path.realpath(base)]).lower() == os.path.realpath(base).lower()
    except ValueError:   # 드라이브가 다름
        return False


def expand_glob(g):
    """'*.{json,md} a.txt' → ['*.json', '*.md', 'a.txt'] (중괄호를 펼쳐 비밀 파일 이름에 맞는지 볼 수 있게)."""
    out, todo = [], [p for p in re.split(r'\s+', g) if p]
    while todo and len(out) < 200:
        p = todo.pop()
        m = re.search(r'\{([^{}]*)\}', p)
        if m:
            todo += [p[:m.start()] + x + p[m.end():] for x in m.group(1).split(',')]
        else:
            out += [x for x in p.split(',') if x]
    return out


def env_dir(*names):
    for n in names:
        v = os.environ.get(n)
        if v:
            return v
    return ''


def limit_dirs():
    """작업 폴더 제한 목록(None = 제한 없음). 값이 깨져 있으면 예외 → main 이 막는다."""
    v = os.environ.get('RC_DIRS')
    if v is None or v.strip() == '*':
        return None
    dirs = json.loads(v)
    if not isinstance(dirs, list):
        raise ValueError('RC_DIRS')
    return [d for d in dirs if isinstance(d, str) and os.path.isabs(d)]


def allowed(full, dirs):
    """들어가도 되는 곳: 고른 폴더 + 임시 폴더 + 계획 파일."""
    return any(inside(full, z) for z in list(dirs) + [TEMP, PLANS] if z)


# 작업 폴더 제한 중에 쓸 수 있는 도구(모르는 도구·MCP·LSP·Skill 은 경로를 확인할 수 없으므로 막는다)
LIMIT_TOOLS = {'Read', 'Write', 'Edit', 'MultiEdit', 'NotebookEdit', 'Glob', 'Grep', 'LS', 'WebFetch', 'WebSearch',
               'Agent', 'Task', 'TodoWrite', 'ToolSearch', 'ExitPlanMode', 'EnterPlanMode',
               'Bash', 'PowerShell', 'BashOutput', 'KillShell', 'TaskOutput', 'TaskStop'}
SHELL_TOOLS = {'Bash', 'PowerShell', 'BashOutput', 'KillShell', 'Monitor'}


def check_dirs(tool, inp, cwd, dirs):
    """작업 폴더 제한 위반(없으면 None). 파일 도구는 경로로, 명령은 실행 위치(cwd)로 본다."""
    def full(p):
        return os.path.abspath(os.path.join(cwd, p))
    if tool in SHELL_TOOLS and os.environ.get('RC_SHELL') == '0':
        return '명령 실행 꺼짐', tool   # 사이트 설정에서 명령 실행을 끈 요청
    if tool not in LIMIT_TOOLS:
        return '허용 안 된 도구', tool
    if tool in ('Bash', 'PowerShell'):
        # 다리가 Claude 를 고른 폴더에서 켜고(--add-dir), Claude Code 가 셸 위치를 그 폴더들 안으로 되돌린다. 여기선 한 번 더 확인
        return None if allowed(cwd, dirs) else ('허용 안 된 폴더', cwd)
    paths = [inp.get(k) for k in ('file_path', 'notebook_path', 'path') if isinstance(inp.get(k), str) and inp.get(k)]
    if tool in ('Glob', 'Grep') and not paths:
        paths = [cwd]   # 경로를 안 주면 지금 위치에서 찾음
    for p in paths:
        # ~(홈)·%변수%·$변수 는 도구가 따로 펼칠 수 있어 경로를 확정할 수 없으므로 막는다
        if p.lstrip().startswith('~') or '%' in p or '$' in p or not allowed(full(p), dirs):
            return '허용 안 된 폴더', p
    if tool == 'Glob':   # 패턴에 위 폴더(..)·중괄호·홈·루트·다른 드라이브가 들어가면 경로를 벗어날 수 있음
        pat = str(inp.get('pattern') or '')
        if '..' in pat or any(c in pat for c in '{}~%$') or pat.startswith(('/', '\\')) or os.path.isabs(pat) or re.match(r'[A-Za-z]:', pat):
            return '허용 안 된 폴더', pat
    if tool in ('Write', 'Edit', 'MultiEdit', 'NotebookEdit'):   # 다음 실행에 명령·훅·MCP 로 쓰일 수 있는 설정은 고른 폴더 안이라도 못 고침
        for p in paths:
            parts = [x.lower() for x in re.split(r'[\\/]+', full(p))]
            if '.claude' in parts or parts[-1] in ('.mcp.json', '.claude.json'):
                return '보호 장치 고치기', p
    return None


def check(tool, inp):
    """막을 이유(없으면 None)."""
    if tool in ('Bash', 'PowerShell'):
        cmd = str(inp.get('command') or '')
        for why, rule in CMD_RULES:
            m = re.search(rule, cmd, re.I)
            if m:
                return why, cmd
        return None
    if tool == 'Glob':   # 파일 이름만 보여 줌(내용 없음)
        return None
    if tool == 'Grep':   # 폴더를 통째로 찾으면 비밀 파일 내용이 나올 수 있음
        for k in ('path', 'glob'):
            v = str(inp.get(k) or '')
            if not v:
                continue
            full = os.path.abspath(v).lower() if k == 'path' else v.lower()
            # glob 은 .ignore 를 무시하고 그 파일까지 찾으므로(*.json 등) 비밀 파일 이름에 맞는 glob 은 막는다
            hits_secret = k == 'glob' and any(fnmatch.fnmatch(n, pat) for pat in expand_glob(full)
                                              for n in ('sync.json', 'study-helper/sync.json', 'remote_claude.json', '.env', '.dev.vars', 'bridge.json', 'dm-reply/bridge.json'))
            if hits_secret or SECRET_PATH.search(full) or re.search(r'sync[.*?]|remote_claude[.*?]|study-helper', full) or any(inside(full, d) for d in SECRET_DIRS):
                return '비밀 값 읽기', v
        return None
    path = str(inp.get('file_path') or inp.get('notebook_path') or inp.get('path') or '')
    if not path:
        return None
    full = os.path.abspath(path).lower()
    if SECRET_PATH.search(full):
        return '비밀 값 읽기', path
    if tool in ('Write', 'Edit', 'MultiEdit', 'NotebookEdit'):
        if SELF_PATH.search(full):
            return '보호 장치 고치기', path
        if not (inside(full, ROOT) or inside(full, TEMP) or inside(full, PLANS)):
            return '프로젝트 밖 파일 쓰기', path
    return None


def log_hit(why, what, ok):
    log = os.environ.get('RC_GUARD_LOG')
    if log:
        try:
            with open(log, 'a', encoding='utf-8') as f:
                f.write(json.dumps({'why': why, 'what': ' '.join(str(what).split())[:200], 'allowed': ok}, ensure_ascii=False) + '\n')
        except Exception:
            pass


def main():
    danger_ok = os.environ.get('RC_ALLOW_DANGER') == '1'
    try:
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
    try:
        dirs = None
        dirs = limit_dirs()
        data = json.loads(sys.stdin.buffer.read().decode('utf-8'))
        tool, inp = str(data.get('tool_name') or ''), data.get('tool_input') or {}
        cwd = str(data.get('cwd') or os.getcwd())
        hard = check_dirs(tool, inp, cwd, dirs) if dirs is not None else None
        hit = None if hard else check(tool, inp)
    except Exception as e:   # 고장 나면 막는다(위험 허용한 요청이라도 작업 폴더 제한이 걸려 있으면 막음)
        if danger_ok and os.environ.get('RC_DIRS', '*').strip() == '*':
            return 0
        sys.stderr.write(f'[rc_guard] 원격 요청 보호 장치가 이 도구를 확인하지 못해 막았습니다({type(e).__name__}).\n')
        return 2
    if hard:   # 작업 폴더 제한은 '위험 허용'으로도 풀리지 않는다
        why, what = hard
        log_hit(why, what, False)
        names = ', '.join(os.path.basename(d.rstrip('\\/')) or d for d in dirs) or '없음'
        sys.stderr.write(f'[rc_guard] 원격 요청은 사이트 설정의 "작업 폴더"에서 고른 폴더만 쓸 수 있습니다: {str(what)[:120]}\n'
                         f'허용된 폴더: {names}. 다른 폴더가 필요하면 사용자에게 원격 Claude 사이트의 설정 > 작업 폴더에서 추가해 달라고 안내하세요. 다른 방법으로 우회하지 마세요.\n')
        return 2
    if not hit:
        return 0
    why, what = hit
    log_hit(why, what, danger_ok)
    if danger_ok:
        return 0
    sys.stderr.write(f'[rc_guard] 원격 요청에서는 위험한 작업({why})을 막아 두었습니다: {str(what)[:120]}\n'
                     '필요하면 사용자에게 원격 Claude 사이트에서 "위험 명령 허용"을 켜고 다시 보내 달라고 안내하세요. 다른 방법으로 우회하지 마세요.\n')
    return 2


if __name__ == '__main__':
    sys.exit(main())
