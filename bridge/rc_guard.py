# -*- coding: utf-8 -*-
"""원격 Claude 위험 명령 막기(PreToolUse 훅). 원격 요청을 실행할 때만 remote_claude.py 가 --settings 로 붙인다.

- 막는 것: 배포·푸시, 원격 DB 쓰기, 폴더 통째 삭제, 시스템 설정 바꾸기, 내려받아 바로 실행, 비밀 값 읽기,
  이 보호 장치 자체(rc_guard·remote_claude.py·.claude/settings) 고치기, 프로젝트 밖 파일 쓰기.
- 막으면 종료 코드 2 + 이유(stderr) → Claude 는 그 도구를 못 쓰고 이유를 본다.
  막은 기록은 RC_GUARD_LOG 파일에 한 줄씩(JSON) 남기고, 다리가 사이트에 '위험 명령을 막았어요' 경고로 보낸다.
- 사이트에서 '위험 명령 허용'을 켜고 보낸 요청은 RC_ALLOW_DANGER=1 → 막지 않고 기록만 남긴다.
- 훅이 고장 나면(입력을 못 읽음·예외) 막는다(fail-closed). bypassPermissions 로 돌기 때문에 열어 두면 그대로 실행된다.
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


def main():
    allowed = os.environ.get('RC_ALLOW_DANGER') == '1'
    try:
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass
    try:
        data = json.loads(sys.stdin.buffer.read().decode('utf-8'))
        hit = check(str(data.get('tool_name') or ''), data.get('tool_input') or {})
    except Exception as e:   # 고장 나면 막는다(허용한 요청만 통과)
        if allowed:
            return 0
        sys.stderr.write(f'원격 요청 보호 장치가 이 도구를 확인하지 못해 막았습니다({type(e).__name__}).\n')
        return 2
    if not hit:
        return 0
    why, what = hit
    log = os.environ.get('RC_GUARD_LOG')
    if log:
        try:
            with open(log, 'a', encoding='utf-8') as f:
                f.write(json.dumps({'why': why, 'what': ' '.join(str(what).split())[:200], 'allowed': allowed}, ensure_ascii=False) + '\n')
        except Exception:
            pass
    if allowed:
        return 0
    sys.stderr.write(f'[rc_guard] 원격 요청에서는 위험한 작업({why})을 막아 두었습니다: {str(what)[:120]}\n'
                     '필요하면 사용자에게 원격 Claude 사이트에서 "위험 명령 허용"을 켜고 다시 보내 달라고 안내하세요. 다른 방법으로 우회하지 마세요.\n')
    return 2


if __name__ == '__main__':
    sys.exit(main())
