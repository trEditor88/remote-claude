# -*- coding: utf-8 -*-
"""원격 Claude 다리: 원격 Claude 사이트(시험지 관리자 계정으로 로그인)에서 보낸 요청을
이 PC 의 Claude Code 로 실행하고 결과를 서버에 돌려준다.

  python tools/remote_claude.py            # 계속 실행(5초마다 확인). 끄려면 Ctrl+C
  python tools/remote_claude.py --once     # 한 번만 확인
  pythonw tools/remote_claude.py           # 창 없이(시작프로그램 바로가기가 이렇게 켬). 기록은 tools/remote_claude.log

- 이미 켜져 있으면 두 번째는 바로 끝난다(127.0.0.1:47213 포트로 확인).
- PC 는 서버로 나가는 요청만 한다(포트를 열지 않음). 인증은 study-helper/sync.json 의 key(워커 키).
- 작업 폴더는 D:\\AI_HEO, 한 요청당 시간 제한 없음(사이트 '중지'로 끔)·최대 150턴. 같은 대화(thread)의 요청은 서버가 준 sessionId 로 이어 간다.
- 실행 중에는 몇 초마다 작업 기록(읽은 파일·실행한 명령)을 서버에 보내고, 사이트에서 '중지'를 누르면 Claude 를 끈다.
- 서버 주소는 sync.json 의 url(Cloudflare Worker).
- 요청에 사진이 붙어 있으면 remote-claude-inbox 폴더에 저장하고, 그 경로를 요청 앞에 적어 Claude 가 Read 로 보게 한다.
- 작업 폴더 제한(v2, 2026-10-11): 사이트 설정 '작업 폴더'에서 고른 폴더(job.dirs)에서만 Claude 를 실행한다.
  고른 폴더 첫째를 실행 위치로, 나머지는 --add-dir 로 주고, 보호 장치(rc_guard.py)에 RC_DIRS 로 넘겨 밖을 막는다.
  ['*'] = 작업 폴더 전체, 비어 있으면 사진 받는 폴더(remote-claude-inbox)에서 대화만. 서버는 v2 가 아닌 다리에 요청을 주지 않는다.
"""
import base64, hashlib, glob, json, os, queue, re, shutil, socket, subprocess, sys, threading, time, urllib.error, urllib.request

# 두 가지로 쓴다
#  - 관리자 PC(D:\AI_HEO\tools): study-helper/sync.json 의 워커 키로 관리자 계정 요청을 받고, 작업 폴더는 D:\AI_HEO
#  - 다른 사람 PC: 사이트 설정 '내 PC 연결'에서 받은 연결 코드로 그 사람 요청만 받는다.
#      python remote_claude.py --key <연결 코드> --dir <작업 폴더>   (처음 한 번. 옆의 remote_claude.json 에 저장)
#      python remote_claude.py --install                            (로그인하면 자동 실행 + 지금 켜기)
HERE = os.path.dirname(os.path.abspath(__file__))
try:   # 구독 사용량 한도에 걸리면 API 키로 다시 실행(이 PC 에만 있는 파일. 다른 사람 PC 에는 없으면 그냥 안 씀)
    sys.path.insert(0, HERE)
    import api_fallback as AF
except Exception:
    AF = None
DEFAULT_API ='https://exam-api.dawn-sea-4052.workers.dev'
CONF = os.path.join(HERE, 'remote_claude.json')
LEGACY = os.path.join(os.path.dirname(HERE), 'study-helper', 'sync.json')


def load_conf(argv):
    def arg(name):
        i = argv.index(name) if name in argv else -1
        return argv[i + 1] if 0 <= i < len(argv) - 1 else None
    conf = {}
    if os.path.exists(CONF):
        try:
            conf = json.load(open(CONF, encoding='utf-8'))
            if not isinstance(conf, dict):
                raise ValueError('not an object')
        except Exception as e:   # 깨진 설정으로 잠금이 풀리거나 관리자 키로 바뀌지 않게 시작하지 않는다
            raise SystemExit(f'설정 파일을 읽지 못했어요({type(e).__name__}): {CONF}\n고치거나 지우고 다시 연결하세요.')
    changed = False
    for k, flag in (('key', '--key'), ('dir', '--dir'), ('url', '--url')):
        v = arg(flag)
        if v:
            conf[k] = os.path.abspath(v) if k == 'dir' else v.strip()
            changed = True
    # --locked: 이 PC 주인이 거는 상한(남의 계정을 내 PC 에 연결할 때). 사이트에서 무엇을 골라도
    # 작업 폴더 밖 금지·명령 실행 끔·위험 허용 끔·API 대체 안 씀. 한 번 켜면 remote_claude.json 을 고쳐야만 풀림
    if '--locked' in argv and not conf.get('locked'):
        conf['locked'] = True
        changed = True
    # 다른 사람 PC 처음 실행: 연결 코드를 명령줄에 쓰면 PowerShell 기록에 남으므로 여기서 묻는다(입력이 화면에 안 보임)
    if not conf.get('key') and (conf.get('locked') or not os.path.exists(LEGACY)) and __name__ == '__main__' and sys.stdin and sys.stdin.isatty():
        import getpass
        k = getpass.getpass('원격 Claude 사이트의 연결 코드를 붙여 넣고 Enter (화면에 안 보여요): ').strip()
        if k:
            conf['key'] = k
            changed = True
    if changed:
        with open(CONF, 'w', encoding='utf-8') as f:
            json.dump(conf, f, ensure_ascii=False, indent=2)
    LOCKED[0] = bool(conf.get('locked'))
    if LOCKED[0] and not conf.get('key'):   # 잠금 다리는 관리자 키(sync.json)로 내려가지 않는다
        return conf.get('url') or DEFAULT_API, '', os.path.abspath(conf.get('dir') or HERE), False
    if conf.get('key'):
        return conf.get('url') or DEFAULT_API, conf['key'], os.path.abspath(conf.get('dir') or HERE), False
    if os.path.exists(LEGACY):
        c = json.load(open(LEGACY, encoding='utf-8'))
        return c.get('url') or DEFAULT_API, c['key'], os.path.dirname(HERE), True
    return DEFAULT_API, '', HERE, False


LOCKED = [False]
API, KEY, ROOT, LEGACY_MODE = load_conf(sys.argv)
LOCKED = LOCKED[0]
if LOCKED:
    AF = None   # 잠금 다리는 이 PC 의 API 키로 대신 실행하지 않는다(남의 요청에 내 돈이 나가지 않게)


def locked_problem():
    """잠금 다리를 시작하면 안 되는 이유('' = 괜찮음). 작업 폴더가 다리 폴더와 겹치면 Claude 가 다리·보호 장치 옆에
    json.py 같은 파일을 심어 다음 실행 때 PC 주인 권한으로 돌릴 수 있고, 관리자 프로젝트와 겹치면 그 파일·비밀에 닿는다."""
    if not LOCKED:
        return ''
    if LEGACY_MODE:
        return '잠금 다리가 관리자 키로 시작하려 해요. remote_claude.json 에 연결 코드(key)를 넣어 주세요.'
    nc = lambda p: os.path.normcase(os.path.realpath(p))
    root, here = nc(ROOT), nc(HERE)
    if root == here or root.startswith(here + os.sep) or here.startswith(root + os.sep):
        return '작업 폴더(--dir)가 다리 폴더와 겹쳐요. 다리 폴더 밖의 다른 폴더를 정해 주세요.'
    p = root
    while True:   # 작업 폴더 자신·위 폴더·바로 아래 폴더에 관리자 프로젝트(study-helper/sync.json)가 있으면 거절
        if os.path.exists(os.path.join(p, 'study-helper', 'sync.json')):
            return '작업 폴더가 관리자 프로젝트 폴더와 겹쳐요. 따로 만든 빈 폴더를 정해 주세요.'
        up = os.path.dirname(p)
        if up == p:
            break
        p = up
    try:
        if any(os.path.exists(os.path.join(root, n, 'study-helper', 'sync.json')) for n in os.listdir(root)):
            return '작업 폴더 안에 관리자 프로젝트 폴더가 있어요. 따로 만든 빈 폴더를 정해 주세요.'
    except OSError:
        pass
    return ''
# 한 PC 에 다리를 여러 개(관리자 다리 + 남의 계정 다리) 띄울 수 있게, 중복 실행 확인 포트와 자동 실행 바로가기를 다리 폴더마다 따로
LOCK_PORT = 47213 if LEGACY_MODE else 47300 + int(hashlib.sha1(os.path.normcase(HERE).encode('utf-8')).hexdigest()[:6], 16) % 600
LNK_NAME = '원격 Claude 다리.lnk' if LEGACY_MODE else f'원격 Claude 다리 ({os.path.basename(HERE)}).lnk'
TIMEOUT_S = 0       # 0 = 시간 제한 없음(2026-10-09 사용자 지시). 멈추려면 사이트의 '중지'
INBOX = os.path.join(ROOT, 'remote-claude-inbox')
EXT = {'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/gif': 'gif'}
POLL_S = 5
IDLE_POLL_S = 15
MAX_PAR = 3   # 동시에 실행할 요청 수(다른 대화끼리만 겹침. 같은 대화는 서버가 차례로 넘김)
DRAIN = os.path.join(HERE, 'remote_claude.drain')   # 이 파일이 있으면 새 요청을 받지 않고, 실행 중인 요청이 다 끝나면 다리를 끈다(재시작용)
_dir_cv, _dir_busy = threading.Condition(), []   # 지금 '고치는' 요청들이 쓰는 폴더 묶음
WAITING = set()   # 폴더가 비길 기다리는 요청 id


def dir_claim(job):
    """고치는 요청(읽기만·앱으로 보내기 제외)의 폴더 묶음. '*' 는 전체(모든 폴더와 겹침), 비면 대화만(안 겹침)."""
    if job.get('mode') in ('plan', 'open') or str(job.get('model') or '').startswith('local-'):   # 로컬 AI 는 파일을 안 건드림
        return set()
    d = job.get('dirs')
    return {'*'} if d == ['*'] else {n for n in (d if isinstance(d, list) else []) if isinstance(n, str)}


def _overlap(a, b):
    return bool(a and b and ('*' in a or '*' in b or a & b))


def wait_dirs(job, claim):
    """같은 폴더를 고치는 다른 요청이 끝날 때까지 기다린다(두 Claude 가 같은 파일·git 을 동시에 고치지 않게).
    기다리는 동안 사이트에 표시하고 중지 요청을 확인한다. 중지되면 False."""
    last = 0.0
    with _dir_cv:
        while any(_overlap(claim, c) for c in _dir_busy):
            WAITING.add(job['id'])
            if time.time() - last >= 10:
                last = time.time()
                _dir_cv.release()
                try:
                    pr = post({'action': 'rcProgress', 'key': KEY, 'id': job['id'], 'progress': '같은 폴더를 고치는 다른 요청이 끝나길 기다리는 중…'}, timeout=15)
                except Exception:
                    pr = {}
                finally:
                    _dir_cv.acquire()
                if pr.get('cancel'):
                    WAITING.discard(job['id'])
                    return False
            _dir_cv.wait(2)
        WAITING.discard(job['id'])
        _dir_busy.append(claim)
    return True


def dir_release(claim):
    with _dir_cv:
        if claim in _dir_busy:
            _dir_busy.remove(claim)
        _dir_cv.notify_all()
PROGRESS_S = 3      # 작업 기록이 바뀌었으면 이 간격으로 보냄
CHECK_S = 5         # 바뀐 게 없어도 이 간격으로 중지 요청 확인
NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)   # pythonw 에서 claude 창이 뜨지 않게
TOOL_KO = {'Read': '읽기', 'Write': '새 파일', 'Edit': '수정', 'MultiEdit': '수정', 'NotebookEdit': '노트 수정',
           'Bash': '명령', 'PowerShell': '명령', 'Grep': '검색', 'Glob': '파일 찾기', 'WebFetch': '웹 읽기',
           'WebSearch': '웹 검색', 'Agent': '도우미', 'Task': '도우미', 'TodoWrite': '할 일 정리', 'Skill': '스킬',
           'ToolSearch': '도구 준비', 'ExitPlanMode': '계획 정리'}


def post(body, timeout=30):
    req = urllib.request.Request(API, data=json.dumps(body).encode('utf-8'),
                                 headers={'Content-Type': 'application/json', 'User-Agent': 'remote-claude/2'}, method='POST')
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode('utf-8'))


def claude_exe():
    """Claude 데스크톱 앱이 깔아 둔 가장 최신 claude.exe (없으면 PATH 의 claude)."""
    hits = glob.glob(os.path.join(os.environ.get('APPDATA', ''), 'Claude', 'claude-code', '*', '*', 'claude.exe'))
    def ver(p):
        v = os.path.basename(os.path.dirname(os.path.dirname(p)))
        return tuple(int(x) if x.isdigit() else 0 for x in v.split('.'))
    return sorted(hits, key=ver)[-1] if hits else (shutil.which('claude') or 'claude')   # npm 으로 깐 claude.cmd 도 찾음


def child_env():
    """claude 에 넘길 환경변수. ANTHROPIC_API_KEY 가 있으면 /login 계정 대신 그 키를 써서
    'Invalid API key' 로 실패하므로 뺀다. Claude 앱 세션 안에서 다리를 켠 경우의 세션 변수도 뺀다."""
    drop = ('ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'CLAUDECODE') if LEGACY_MODE or LOCKED else ('CLAUDECODE',)   # 잠금 다리: 이 PC 의 키로 남의 요청이 과금되지 않게   # 다른 사람 PC 는 API 키로 쓸 수도 있어 그대로 둠
    env = {k: v for k, v in os.environ.items()
           if k not in drop and not k.startswith(('CLAUDE_CODE_', 'CLAUDE_AGENT_SDK'))}
    env.update(PYTHONUTF8='1', PYTHONIOENCODING='utf-8')   # 보호 훅·파이썬 명령이 한글을 cp949 로 읽다 고장 나지 않게
    return env


def tool_line(name, inp):
    """도구 사용 한 건 → '읽기 · tools/remote_claude.py' 같은 한 줄."""
    label = TOOL_KO.get(name) or name.split('__')[-1]
    inp = inp if isinstance(inp, dict) else {}
    detail = ''
    for k in ('file_path', 'notebook_path', 'command', 'pattern', 'path', 'url', 'query', 'description', 'skill', 'prompt'):
        if isinstance(inp.get(k), str) and inp[k].strip():
            detail = inp[k]
            break
    if detail and os.path.isabs(detail) and detail.lower().startswith(ROOT.lower()):
        detail = os.path.relpath(detail, ROOT)
    detail = ' '.join(detail.split())
    return f'{label} · {detail[:90]}' if detail else label


def kill_tree(p):
    """claude 와 그 아래에서 돈 명령(python·node 등)까지 함께 끈다."""
    try:
        subprocess.run(['taskkill', '/PID', str(p.pid), '/T', '/F'], capture_output=True, timeout=20, creationflags=NO_WINDOW)
    except Exception:
        pass
    try:
        p.kill()
    except Exception:
        pass


BRIDGE_V = 5   # 3: 'Claude 앱으로 보내기'(mode open) 요청을 안다. 4: 로컬 AI(model local-*) 요청을 안다. 5: local-deepseek·local-free 를 안다. 서버는 그보다 옛 다리에 그 요청을 주지 않는다
SKIP_DIRS = ('__pycache__', 'node_modules', 'gas', 'remote-claude-inbox')


CHAT = os.path.join(INBOX, 'chat')   # 고른 폴더가 없을 때 Claude 가 머무는 빈 폴더(대화만)


def real_dir(p):
    """링크·정션이 아닌 진짜 폴더인가(링크를 고르면 허용 범위가 링크 대상 전체로 넓어지므로 선택지에서 뺀다)."""
    return os.path.isdir(p) and os.path.normcase(os.path.realpath(p)) == os.path.normcase(os.path.abspath(p))


def folder_list():
    """사이트 '작업 폴더'의 선택지: 작업 폴더 바로 아래 폴더들(숨김·배포 클론(*-repo)·캐시·링크 제외)."""
    try:
        names = sorted(n for n in os.listdir(ROOT) if real_dir(os.path.join(ROOT, n))
                       and not n.startswith('.') and n not in SKIP_DIRS and not n.endswith('-repo'))
    except OSError:
        return []
    return names[:150]


def job_files_dir(job):
    return os.path.join(INBOX, 'files', str(job.get('id') or 'x'))   # 이 요청의 사진만(다른 요청 사진·밀린 결과는 못 봄)


def job_dirs(job):
    """(실행 위치, 추가 폴더 목록, RC_DIRS 값). 고른 폴더가 지금 없으면 빼고, 하나도 없으면 빈 대화 폴더에서 대화만."""
    d = job.get('dirs')
    if d == ['*']:
        # 잠금 다리: '전체' 도 작업 폴더 안으로만(제한 없음이 아니라 작업 폴더 전체를 고른 것으로)
        return (ROOT, [], json.dumps([ROOT])) if LOCKED else (ROOT, [], '*')
    names = [n for n in (d if isinstance(d, list) else []) if isinstance(n, str) and n in folder_list()]
    paths = [os.path.join(ROOT, n) for n in names]
    files = job_files_dir(job)
    os.makedirs(CHAT, exist_ok=True)
    extra = [files] if os.path.isdir(files) else []
    if not paths:
        return CHAT, extra, json.dumps([CHAT] + extra)
    return paths[0], paths[1:] + extra, json.dumps(paths + extra)


def save_files(job):
    """사진을 받아 INBOX 에 저장하고 경로 목록을 돌려준다(받지 못한 사진은 건너뜀)."""
    paths = []
    for i, fid in enumerate(job.get('files') or []):
        try:
            r = post({'action': 'rcFile', 'key': KEY, 'id': fid}, timeout=60)
            head, b64 = r['data'].split(',', 1)
            os.makedirs(job_files_dir(job), exist_ok=True)
            path = os.path.join(job_files_dir(job), f"{i + 1}.{EXT.get(head[5:].split(';')[0], 'jpg')}")
            with open(path, 'wb') as fp:
                fp.write(base64.b64decode(b64))
            paths.append(path)
        except Exception as e:
            print(time.strftime('%Y-%m-%d %H:%M:%S'), '사진 받기 실패', fid, e, flush=True)
    return paths


def with_files(prompt, paths):
    if not paths:
        return prompt
    head = [f'[사용자가 사진 {len(paths)}장을 보냈습니다. Read 도구로 열어 보고 요청에 답하세요. '
            'PC 화면에 띄워 달라고 하면 PowerShell 의 Start-Process "ms-photos:viewer?fileName=<경로>" 로 여세요'
            '(.jpg 기본 앱이 없어 경로만 주면 "앱 선택" 창이 뜸).]']
    head += [f'- {p}' for p in paths]
    return '\n'.join(head) + '\n\n' + ('' if prompt == '(사진)' else prompt)


GUARD = os.path.join(HERE, 'rc_guard.py')


def console_python():
    """훅은 표준 입출력을 쓰므로 pythonw 가 아닌 python.exe 로 돌린다."""
    exe = sys.executable or 'python'
    alt = os.path.join(os.path.dirname(exe), 'python.exe')
    return alt if os.path.basename(exe).lower().startswith('pythonw') and os.path.exists(alt) else exe


def guard_settings():
    """원격 요청에만 붙이는 위험 명령 막기 훅(tools/rc_guard.py). 평소 Claude Code 사용에는 영향 없음.
    (Claude Code 의 Windows 격리(sandbox)는 2026-10 현재 이 PC 에서 잠겨 있어(feature gate) 쓰지 못함)
    -I: 다리 폴더에 둔 fnmatch.py 같은 파일이 보호 장치의 표준 모듈을 가로채지 못하게(2026-10-21 재현)."""
    return json.dumps({'hooks': {'PreToolUse': [{'matcher': '*', 'hooks': [{'type': 'command', 'command': f'"{console_python()}" -I "{GUARD}"', 'timeout': 30}]}]}})


def read_guard(path, seen):
    """훅이 남긴 막음/허용 기록 중 새 줄만 → ['막음 · 배포·푸시 · git push …', …]"""
    try:
        with open(path, encoding='utf-8') as f:
            rows = [json.loads(x) for x in f.read().splitlines() if x.strip()]
    except Exception:
        return [], seen
    out = [f"{'허용함' if r.get('allowed') else '막음'} · {r.get('why')} · {r.get('what')}" for r in rows[seen:]]
    return out, len(rows)


def guard_works():
    """보호 장치가 이 PC 에서 실제로 막는지 요청마다 확인(파일 없음·깨짐·파이썬 문제면 bypassPermissions 로 그냥 실행되므로).
    ① 위험 명령(git push) ② 작업 폴더 밖 읽기(위험 허용을 켜도 막혀야 함)는 막고 ③ 고른 폴더 안 읽기는 통과해야 함.
    문제가 없으면 '', 있으면 사용자에게 보여 줄 이유."""
    if not os.path.isfile(GUARD):
        return '다리 폴더에 rc_guard.py 가 없어요'
    probe = os.path.join(ROOT, '__rc_probe__.txt')
    tests = [({'tool_name': 'Bash', 'tool_input': {'command': 'git push origin main  # 한글 확인'}, 'cwd': ROOT}, {'RC_ALLOW_DANGER': '0', 'RC_DIRS': '*'}, 2),
             ({'tool_name': 'Read', 'tool_input': {'file_path': probe}, 'cwd': CHAT}, {'RC_ALLOW_DANGER': '1', 'RC_DIRS': json.dumps([CHAT])}, 2),
             ({'tool_name': 'Read', 'tool_input': {'file_path': os.path.join(CHAT, 'a.txt')}, 'cwd': CHAT}, {'RC_ALLOW_DANGER': '0', 'RC_DIRS': json.dumps([CHAT])}, 0)]
    try:
        for i, (sample, extra, want) in enumerate(tests):
            r = subprocess.run([console_python(), '-I', GUARD], input=json.dumps(sample, ensure_ascii=False).encode('utf-8'), capture_output=True, timeout=30,
                               creationflags=NO_WINDOW, env=dict(child_env(), RC_GUARD_LOG='', RC_ROOT=ROOT, RC_SHELL='1', **extra))   # 실제 실행과 같은 환경
            # 파이썬의 '파일 없음'도 종료 코드 2 라서, 막을 때는 보호 장치가 직접 쓴 표시까지 확인한다
            if r.returncode != want or (want == 2 and b'[rc_guard]' not in r.stderr):
                return ('rc_guard.py 가 옛 버전이거나 고장 났어요(시험 %d). 다리 파일 두 개(remote_claude.py, rc_guard.py)를 함께 새로 받아 주세요' % (i + 1))
        return ''
    except Exception as e:
        return f'rc_guard.py 를 실행하지 못했어요({type(e).__name__})'


def run(job, fresh=False):
    """요청 실행. 구독 사용량 한도에 걸렸으면 저장된 API 키로 한 번 더(하루 상한 안에서)."""
    res = _run(job, fresh)
    res.pop('costUsd', None)
    # 오류로 끝났고 그 메시지가 한도 안내일 때만(정상 답변 본문에 '사용량 한도'가 있어도 다시 돌지 않게)
    if res.get('canceled') or not AF or not res.get('error') or not AF.is_limit(res['error']):
        return res
    who = '원격 ' + str(job.get('id') or '')
    hid, key, left = AF.reserve(who)
    if not hid:
        print(time.strftime('%Y-%m-%d %H:%M:%S'), '사용량 한도 · API 대체 안 됨:', left, flush=True)
        return dict(res, error=(res.get('error') or '')[:200] + f' (API 대체 안 됨: {left})')
    print(time.strftime('%Y-%m-%d %H:%M:%S'), '사용량 한도 → API 키로 다시 실행', job.get('id'), f'(예산 ${left:.2f})', flush=True)
    note = ('[구독 사용량 한도 때문에 같은 요청을 API 로 다시 실행합니다. 앞선 시도가 일부 작업을 했을 수 있으니 '
            '파일 상태를 확인하고 이미 된 일은 되풀이하지 마세요.]\n')
    try:
        res2 = _run(dict(job, prompt=note + job['prompt']), fresh, api=(key, left))
    except Exception:
        AF.settle(hid, None, who)   # 비용을 모르면 잡아 둔 돈을 쓴 것으로
        raise
    cost = res2.pop('costUsd', None)
    if cost is None and res2.get('error') and AF.is_api_limit(res2['error']):
        cost = 0   # API 가 바로 거절(비용 없음) → 잡아 둔 돈을 다 쓴 것으로 치지 않음
    AF.settle(hid, cost, who)
    try:   # 서버에 건수 알림(하루 5건 넘으면 관리자 알림). 실패해도 결과는 그대로
        post({'action': 'apiFallbackLog', 'key': KEY, 'who': who[:40]}, timeout=15)
    except Exception:
        pass
    first = (res.get('danger') or '').strip()
    if first:   # 첫 시도에서 막은 기록도 사이트 경고에 남긴다
        res2['danger'] = (first + '\n' + (res2.get('danger') or '')).strip()[:2000]
    res2['progress'] = (f'구독 사용량 한도라 API 키로 다시 실행했어요(${float(cost or 0):.2f})\n' + (res2.get('progress') or ''))[:4000]
    if res2.get('error'):
        if AF.is_api_limit(res2['error']):   # API 자체도 한도(워크스페이스 지출 한도 등) → 30분 쉬고, 관리자 알림, 사용자 안내
            AF.pause(res2['error'])
            if AF.alert_once():
              try: post({'action': 'pcAlert', 'key': KEY, 'kind': 'api', 'text': ('원격 Claude 요청을 API 로 다시 돌렸지만 API 도 한도로 거절했어요. 30분 동안 API 대체를 쉬어요: ' + res2['error'])[:300]}, timeout=15)
              except Exception: pass
            res2['error'] = ('%s (%s)' % ('AI API 사용 한도에 걸려 지금은 처리하지 못했어요. 30분쯤 뒤 다시 시도해 주세요(관리자에게 알렸어요).', res2['error']))[:300]
        else:
            res2['error'] = ('구독 한도 → API 재실행 실패: ' + res2['error'])[:300]
    return res2


def _run(job, fresh=False, api=None):
    bad = guard_works()
    if bad:
        return {'result': '', 'error': ('PC 의 보호 장치가 동작하지 않아 실행하지 않았어요: ' + bad)[:300], 'sec': 0, 'costUsd': 0}
    paths = save_files(job)
    if job.get('files') and len(paths) < len(job['files']):   # 사진을 못 받았으면 없는 사진에 답하느라 Opus 를 돌리지 않게 멈춘다(로컬 AI 길과 같게, 2026-10-21)
        shutil.rmtree(job_files_dir(job), ignore_errors=True)
        return {'result': '', 'error': '붙인 사진을 PC 가 받지 못했어요. 다시 보내 주세요.', 'sec': 0, 'costUsd': 0}   # API 재실행 안에서 멈춰도 쓴 돈 0 으로 정산
    prompt = with_files(job['prompt'], paths)
    if prompt.startswith('-'):
        prompt = ' ' + prompt   # '-' 로 시작하면 claude 가 옵션으로 읽지 않게
    cmd = [claude_exe(), '-p', prompt, '--output-format', 'stream-json', '--verbose', '--max-turns', '150',
           ]
    guard_log = os.path.join(os.environ.get('TEMP', ROOT), f"rc_guard_{job.get('id', 'x')}.jsonl")
    try:
        os.remove(guard_log)
    except OSError:
        pass
    cwd, extra_dirs, rc_dirs = job_dirs(job)
    cmd += ['--settings', guard_settings()]
    limited = rc_dirs != '*'
    no_shell = limited and (LOCKED or not job.get('shell'))   # 잠금 다리는 명령 실행을 늘 끔
    if limited:   # MCP 서버를 붙이지 않는다(파일·터미널을 다루는 MCP 로 폴더 제한을 돌아가지 못하게)
        cmd += ['--strict-mcp-config']
    # 명령 실행을 끈 경우: 명령 도구를 아예 빼서 폴더 밖으로 나갈 길을 없앤다(보호 장치도 RC_SHELL=0 으로 한 번 더 막음)
    # 잠금 다리: 웹 읽기는 이 PC 의 로컬 서버(llama-swap·허브 등)에도 닿으므로 뺀다(훅도 RC_LOCKED 로 막음). 한 번의 --disallowedTools 로 묶는다
    deny = (['Bash', 'PowerShell', 'Monitor'] if no_shell else []) + (['WebFetch'] if LOCKED else [])
    if deny:
        cmd += ['--disallowedTools'] + deny
    for d in extra_dirs:
        cmd += ['--add-dir', d]
    # 임시 폴더도 요청마다 따로(다른 세션의 임시 파일·보호 장치 기록을 못 보게). 끝나면 지운다
    job_tmp = os.path.join(os.environ.get('TEMP', ROOT), 'rc_jobs', str(job.get('id') or 'x'))
    os.makedirs(job_tmp, exist_ok=True)
    env = dict(child_env(), RC_GUARD_LOG=guard_log, RC_LOCKED='1' if LOCKED else '0', RC_ALLOW_DANGER='1' if job.get('allow') and not LOCKED else '0', RC_ROOT=ROOT, RC_DIRS=rc_dirs, RC_SHELL='0' if no_shell else '1')
    if limited:
        env.update(TEMP=job_tmp, TMP=job_tmp)
    if api:   # API 키로 실행(apiKeyHelper, 키는 환경변수에 안 넣음): 그날 남은 예산만큼만 쓰게 묶는다
        env = AF.api_env(env)
        cmd[cmd.index('--settings') + 1] = AF.with_key(guard_settings(), console_python())
        cmd += ['--max-budget-usd', f'{api[1]:.2f}']
    guard_seen, danger = 0, []
    if job.get('model') in ('sonnet', 'opus', 'fable', 'haiku'):
        cmd += ['--model', job['model']]
    # 읽기만 = plan(파일을 고치지 않음). 아니면 묻지 않고 실행하되 위험한 명령은 위의 훅(rc_guard)이 막는다
    cmd += ['--permission-mode', 'plan' if job.get('mode') == 'plan' else 'bypassPermissions']
    if job.get('title'):
        cmd += ['-n', '원격: ' + ' '.join(job['title'].split())[:40]]
    if job.get('sessionId') and not fresh and not str(job['sessionId']).startswith('local-'):   # 로컬 AI 로 이어 온 대화면 새 Claude 세션
        cmd += ['--resume', job['sessionId']]
    t0 = time.time()
    p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, creationflags=NO_WINDOW)
    lines, err = queue.Queue(), []
    def read_out():
        for raw in p.stdout:
            lines.put(raw)
        lines.put(None)
    threading.Thread(target=read_out, daemon=True).start()
    threading.Thread(target=lambda: err.append(p.stderr.read()), daemon=True).start()

    log, final, st = [], {}, {'model': '', 'session': ''}
    sent, last_sent, last_check, canceled, timed_out = '', 0.0, 0.0, False, False
    while True:
        try:
            raw = lines.get(timeout=1)
        except queue.Empty:
            raw = b''
        if raw is None:
            break
        if raw:
            try:
                j = json.loads(raw.decode('utf-8', 'replace'))
            except Exception:
                j = {}
            st['session'] = j.get('session_id') or st['session']
            if j.get('type') == 'system' and j.get('subtype') == 'init':
                st['model'] = j.get('model') or ''
            elif j.get('type') == 'assistant':
                for b in (j.get('message') or {}).get('content') or []:
                    if b.get('type') == 'tool_use':
                        log.append(tool_line(b.get('name') or '', b.get('input')))
                    elif b.get('type') == 'text' and (b.get('text') or '').strip():
                        log.append('생각 · ' + ' '.join(b['text'].split())[:110])
            elif j.get('type') == 'result':
                final = j
        new, guard_seen = read_guard(guard_log, guard_seen)
        log += new; danger += new
        now = time.time()
        if TIMEOUT_S and now - t0 > TIMEOUT_S:
            kill_tree(p); timed_out = True
            break
        if job.get('id'):
            text = '\n'.join(log[-15:])
            body = None
            if text != sent and now - last_sent >= PROGRESS_S:
                body = {'action': 'rcProgress', 'key': KEY, 'id': job['id'], 'progress': text}
                sent, last_sent = text, now
            elif now - last_check >= CHECK_S:
                body = {'action': 'rcProgress', 'key': KEY, 'id': job['id']}   # 기록 없이 중지 요청만 확인
            if body:
                last_check = now
                try:
                    pr = post(body, timeout=15)
                    # 중지 요청, 또는 허용이 꺼져 이 다리가 거절됨(bad_key) → 바로 끈다
                    if pr.get('cancel') or pr.get('error') == 'bad_key':
                        kill_tree(p); canceled = True
                        break
                except Exception:
                    pass
    try:
        p.wait(timeout=30)
    except Exception:
        kill_tree(p)
    sec = round(time.time() - t0)
    new, guard_seen = read_guard(guard_log, guard_seen)
    log += new; danger += new
    try:
        os.remove(guard_log)
    except OSError:
        pass
    shutil.rmtree(job_tmp, ignore_errors=True)
    skipped = f'… 앞의 {len(log) - 40}단계 생략\n' if len(log) > 40 else ''
    out = {'sessionId': final.get('session_id') or st['session'], 'sec': sec, 'progress': (skipped + '\n'.join(log[-40:]))[:4000],
           'usedModel': st['model'], 'turns': final.get('num_turns') or 0, 'danger': '\n'.join(danger)[:2000],
           'costUsd': final.get('total_cost_usd') if final else None}   # run() 이 빼고 보냄(API 로 쓴 돈 정산용, 모르면 None)
    if canceled:
        return dict(out, result='', error='', canceled=True)
    if timed_out:
        return dict(out, result='', error=f'{TIMEOUT_S // 60}분 안에 끝나지 않아 멈췄습니다.')
    if not final:
        msg = (b''.join(err).decode('utf-8', 'replace').strip() or f'결과 없이 끝났습니다(종료 코드 {p.returncode}).')
        # 작업 폴더를 바꾸면 Claude 세션이 다른 폴더에 있어 이어 가지 못함 → 새 세션으로 한 번 다시
        if job.get('sessionId') and not fresh and 'No conversation found' in msg:
            return run_fresh(job, api)
        return dict(out, result=msg[:60000], error=msg[:300])
    result = str(final.get('result') or '')
    if job.get('sessionId') and not fresh and final.get('is_error') and 'No conversation found' in (result + ' '.join(map(str, final.get('errors') or []))):
        return run_fresh(job, api)
    sub = final.get('subtype')
    is_err = bool(final.get('is_error')) or sub not in (None, 'success')
    why = {'error_max_turns': '150턴 안에 끝내지 못했습니다. "이어서 해"로 계속하거나 요청을 나눠서 보내 주세요.'}.get(sub, str(sub))
    return dict(out, result=result[:60000] or (why if is_err else ''), error=(result[:300] or why) if is_err else '')


def run_fresh(job, api=None):
    """작업 폴더가 바뀌면 Claude 세션이 다른 폴더에 있어 이어 가지 못함 → 새 세션으로 한 번만 다시."""
    return _run(dict(job, prompt='[작업 폴더 설정이 바뀌어 이전 대화 내용 없이 새로 시작합니다]\n' + job['prompt']), fresh=True, api=api)


""" ── 로컬 AI(2026-10-14): 모델이 local-* 인 요청은 Claude 대신 이 PC 의 로컬 LLM(llama-swap, OpenAI 호환)으로 답한다 ──
   도구·파일·명령 없이 글(+사진)만 주고받는다. 대화 기록은 INBOX/local/<세션>.json(세션 id 'local-<hex>')에 두고,
   서버는 그 id 를 Claude 세션 id 처럼 대화(thread)에 저장했다가 다음 요청 때 돌려준다."""
LOCAL_MODELS = {'local-fast': ('qwen-fast', False), 'local-next': ('flash-next', True),
                'local-deepseek': ('deepseek-v4', False), 'local-free': ('flash-next-abliterated', False)}   # (llama-swap 모델 이름, 생각 켜기). 2026-10-29 딥시크·검열 해제판(관리자만)
LOCAL_NOVISION = {'deepseek-v4'}   # 사진을 못 읽는 모델
LOCAL_BUDGET = {'deepseek-v4': 25000}   # 지난 대화+새 글 합계 글자 상한. 딥시크는 문맥 32k 토큰이라 더 작게(한글 ≈ 0.4토큰/자 측정, 최악 대비)
LOCAL_BUDGET_DEF = 50000   # 문맥 64k 토큰 모델(5만 자 ≈ 2만 토큰 + 답 자리). 넘치면 답이 한두 글자에서 끊김(2026-10-29 검열 해제판에서 재현)
LOCAL_DIR = os.path.join(INBOX, 'local')
LOCAL_SID = re.compile(r'^local-[0-9a-f]{20}$')
LOCAL_HIST_CHARS = 30000   # 이어 붙일 지난 대화 글자 상한(한글 ≈ 1자 1토큰. 모델 문맥 64k 토큰 안에서 새 질문·사진·답·생각 16k 자리를 남김)
LOCAL_OPEN = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # 127.0.0.1 요청이 프록시로 새지 않게


def local_url():
    """로컬 LLM 주소: remote_claude.json 의 llm > 환경변수 LOCAL_LLM_URL > 기본. 이 PC 안(127.0.0.1·localhost)만 쓴다."""
    try:
        u = (json.load(open(CONF, encoding='utf-8')) if os.path.exists(CONF) else {}).get('llm')
    except Exception:
        u = None
    u = str(u or os.environ.get('LOCAL_LLM_URL') or 'http://127.0.0.1:8080').rstrip('/')
    return u if re.match(r'^http://(127\.0\.0\.1|localhost)(:\d{1,5})?$', u) else 'http://127.0.0.1:8080'


def local_status():
    """사이트 표시용: 로컬 LLM 서버가 켜져 있는지와 지금 올라와 있는 모델."""
    try:
        with LOCAL_OPEN.open(local_url() + '/running', timeout=3) as r:
            j = json.loads(r.read().decode('utf-8', 'replace'))
        run = j.get('running') if isinstance(j, dict) else j
        names = sorted({str(x.get('model') or '')[:40] for x in (run or []) if isinstance(x, dict) and x.get('model')})
        return {'up': True, 'loaded': names[:4]}
    except Exception:
        return {'up': False, 'loaded': []}


def local_system():
    common = r'D:\llm\common_system.txt'   # 이 PC 에만 있음(편향 줄이는 공통 지시). 없으면 기본 지시만
    base = ('너는 사용자의 PC 에서 돌아가는 로컬 AI 비서다. 한국어로 묻으면 한국어로, 이유 중심으로 짧고 정확하게 답한다. '
            '모르는 것은 모른다고 하고 확실하지 않은 사실은 추정이라고 밝힌다. 너는 파일을 읽거나 명령을 실행할 수 없다.\n'
            # 로컬 모델은 글 쓰는 속도가 느려(초당 10~20토큰) 같은 코드를 통째로 다시 쓰면 오래 걸린다(2026-10-17)
            '이미 대화에 나온 코드를 고칠 때는 전체를 다시 쓰지 말고 바뀐 부분만 이 형식으로 보여 준다:\n'
            '<<<<<<< 찾기\n(원래 코드 몇 줄, 원본과 글자 하나까지 똑같이)\n=======\n(바꿀 코드)\n>>>>>>> 바꾸기\n'
            '고칠 곳이 여러 군데면 이 묶음을 여러 개 쓴다. 사용자가 전체 코드를 달라고 하면 그때만 전체를 쓴다.')
    try:
        extra = open(common, encoding='utf-8').read().strip() if os.path.exists(common) else ''
    except OSError:
        extra = ''
    return base + ('\n\n' + extra if extra else '')


def local_load(sid):
    if not (isinstance(sid, str) and LOCAL_SID.match(sid)):
        return []
    try:
        h = json.load(open(os.path.join(LOCAL_DIR, sid + '.json'), encoding='utf-8'))
        return [m for m in h if isinstance(m, dict) and m.get('role') in ('user', 'assistant') and isinstance(m.get('content'), str)]
    except Exception:
        return []


def local_save(sid, hist):
    os.makedirs(LOCAL_DIR, exist_ok=True)
    fp = os.path.join(LOCAL_DIR, sid + '.json')
    with open(fp + '.tmp', 'w', encoding='utf-8') as f:
        json.dump(hist, f, ensure_ascii=False)
    os.replace(fp + '.tmp', fp)


def local_trim(hist, limit=LOCAL_HIST_CHARS):
    """오래된 것부터 빼서 limit 글자 안으로(질문·답 짝이 깨지지 않게 둘씩)."""
    while len(hist) > 2 and sum(len(m['content']) for m in hist) > limit:
        hist = hist[2:]
    over = sum(len(m['content']) for m in hist) - max(0, limit)
    if over > 0:   # 남은 한 짝 자체가 너무 길면(긴 글을 붙여 넣은 경우) 긴 쪽부터 가운데를 줄인다 — 안 그러면 문맥이 꽉 차 답이 끊김
        hist = [dict(m) for m in hist]
        for m in sorted(hist, key=lambda m: -len(m['content'])):
            c = m['content']
            keep = max(400, len(c) - over - 12)
            if keep >= len(c):
                continue
            m['content'] = c[:keep // 2] + '\n…(줄임)…\n' + c[len(c) - (keep - keep // 2):]
            over -= len(c) - len(m['content'])
            if over <= 0:
                break
    return hist


def run_local(job):
    t0 = time.time()
    name, think = LOCAL_MODELS[job['model']]
    old = local_load(job.get('sessionId'))
    sid = job['sessionId'] if old else 'local-' + os.urandom(10).hex()   # 새 대화거나 Claude 세션이던 대화면 새 기록
    paths = save_files(job)
    if job.get('files') and len(paths) < len(job['files']):   # 사진을 못 받았으면 없는 사진에 답하지 않게 멈춘다
        shutil.rmtree(job_files_dir(job), ignore_errors=True)
        return {'sessionId': job.get('sessionId') or '', 'usedModel': name, 'turns': 0, 'danger': '', 'result': '', 'sec': round(time.time() - t0),
                'error': '붙인 사진을 PC 가 받지 못했어요. 다시 보내 주세요.'}
    if paths and name in LOCAL_NOVISION:
        shutil.rmtree(job_files_dir(job), ignore_errors=True)
        return {'sessionId': job.get('sessionId') or '', 'usedModel': name, 'turns': 0, 'danger': '', 'result': '', 'sec': round(time.time() - t0),
                'error': '딥시크는 사진을 읽지 못해요. 사진은 다른 모델로 보내 주세요.'}
    text = '' if job['prompt'] == '(사진)' and paths else job['prompt']
    content = text or '이 사진을 설명해 줘.'
    if paths:
        parts = []
        for p in paths:
            mime = 'image/' + {'jpg': 'jpeg'}.get(p.rsplit('.', 1)[-1], p.rsplit('.', 1)[-1])
            parts.append({'type': 'image_url', 'image_url': {'url': f'data:{mime};base64,' + base64.b64encode(open(p, 'rb').read()).decode()}})
        content = parts + [{'type': 'text', 'text': content}]
    budget = LOCAL_BUDGET.get(name, LOCAL_BUDGET_DEF)
    if len(text) > budget:   # 새 글 하나가 모델이 읽을 수 있는 양을 넘으면 보내지 않고 알린다
        shutil.rmtree(job_files_dir(job), ignore_errors=True)
        return {'sessionId': job.get('sessionId') or '', 'usedModel': name, 'turns': 0, 'danger': '', 'result': '', 'sec': round(time.time() - t0),
                'error': f'글이 {len(text):,}자라 이 모델이 한 번에 읽을 수 있는 양(약 {budget:,}자)을 넘어요. 나눠서 보내 주세요.'}
    hist = local_trim(old, min(LOCAL_HIST_CHARS, budget - len(text)))   # 지난 대화+새 글이 budget 안에 들게(긴 글 한 짝도 줄임)
    body = {'model': name, 'stream': True, 'max_tokens': 16384 if think else 8192,
            'messages': [{'role': 'system', 'content': local_system()}] + hist + [{'role': 'user', 'content': content}],
            'chat_template_kwargs': {'enable_thinking': think}}
    req = urllib.request.Request(local_url() + '/v1/chat/completions', data=json.dumps(body).encode('utf-8'),
                                 headers={'Content-Type': 'application/json'})
    out = {'sessionId': sid, 'usedModel': name, 'turns': 0, 'danger': ''}
    # 연결·읽기는 따로 스레드에서(llama-swap 이 모델을 올리거나 다른 요청이 끝나길 기다리는 동안에도 진행 표시·중지 확인을 하려고)
    q, hold = queue.Queue(), {'stop': False}
    def reader():
        resp = None
        try:
            resp = LOCAL_OPEN.open(req, timeout=3600)
            hold['resp'] = resp
            if hold['stop']:
                return
            q.put(('open', None))
            for raw in resp:
                q.put(('line', raw))
            q.put(('end', None))
        except Exception as e:
            q.put(('err', e))
        finally:   # 닫기는 읽는 스레드만(다른 스레드가 close 하면 읽기가 끝날 때까지 막힘)
            try:
                resp and resp.close()
            except Exception:
                pass
    threading.Thread(target=reader, daemon=True).start()
    answer, reason, ntok, t_first, opened, finished = [], [], 0, None, False, False
    last_sent, last_check, canceled, err = 0.0, 0.0, False, ''
    try:
        while True:
            try:
                kind, v = q.get(timeout=1)
            except queue.Empty:
                kind, v = None, None
            if kind == 'err':
                if not opened:
                    if isinstance(v, urllib.error.HTTPError):   # 서버는 켜져 있지만 거절(모델 없음·문맥 넘침 등)
                        try:
                            detail = ' '.join(v.read(400).decode('utf-8', 'replace').split())
                        except Exception:
                            detail = ''
                        why = f'로컬 LLM 이 요청을 거절했어요(HTTP {v.code}). ' + ('글이 이 모델이 한 번에 읽을 수 있는 양을 넘었을 수 있어요. 글을 줄이거나 새 대화로 시작해 주세요. ' if v.code in (400, 413) else '') + detail[:150]
                    else:
                        why = f'이 PC 의 로컬 LLM 서버에 연결하지 못했어요({type(v).__name__}). 서버가 켜져 있는지 확인해 주세요.'
                    return dict(out, sessionId=job.get('sessionId') or '', result='', sec=round(time.time() - t0), error=why[:300])
                err = f'로컬 LLM 응답이 끊겼어요({type(v).__name__}).'
                break
            if kind == 'end':
                if not finished:   # [DONE]·finish_reason 없이 끝남 = 중간에 끊김
                    err = '로컬 LLM 응답이 중간에 끊겼어요.'
                break
            opened = opened or kind == 'open'
            if kind == 'line':   # SSE: 'data: {...}' 줄
                line = v.decode('utf-8', 'replace').strip()
                data = line[5:].strip() if line.startswith('data:') else ''
                if data == '[DONE]':
                    finished = True
                    break
                try:
                    ch = (json.loads(data).get('choices') or [{}])[0] if data else {}
                    d = ch.get('delta') or {}
                    finished = finished or bool(ch.get('finish_reason'))
                    if ch.get('finish_reason') == 'length':   # 답 길이 상한이나 문맥이 꽉 차서 멈춤
                        hold['length'] = True
                except Exception:
                    d = {}
                if d.get('reasoning_content'):
                    reason.append(d['reasoning_content']); ntok += 1
                if d.get('content'):
                    answer.append(d['content']); ntok += 1
                    t_first = t_first or time.time()
            now = time.time()
            if now - last_sent >= PROGRESS_S or now - last_check >= CHECK_S:
                a = ''.join(answer)
                steps = [f'{name} 에 보냄' + (' · 생각 켬' if think else '')]
                if not opened:
                    steps.append(f'로컬 LLM 차례를 기다리는 중 · {round(now - t0)}초 (모델을 올리거나 다른 작업이 끝나길 기다려요)')
                elif not reason and not a:
                    steps.append('질문을 읽는 중…')
                if reason:
                    steps.append(f'생각하는 중 · {len("".join(reason)):,}자')
                if a:
                    steps.append(f'답 쓰는 중 · {len(a):,}자 · 약 {len(a) / max(0.1, now - t_first):.0f}자/초')
                    steps.append('미리 보기 · ' + ' '.join(a[-120:].split()))
                body2 = {'action': 'rcProgress', 'key': KEY, 'id': job['id']}
                if now - last_sent >= PROGRESS_S:
                    body2['progress'] = '\n'.join(steps)[:4000]
                    last_sent = now
                last_check = now
                try:
                    pr = post(body2, timeout=15)
                    if pr.get('cancel') or pr.get('error') == 'bad_key':
                        canceled = True
                        break
                except Exception:
                    pass
    finally:
        hold['stop'] = True
        try:   # 소켓을 끊어 읽던 스레드를 바로 깨운다(llama-swap 도 생성을 멈춤). close 는 그 스레드가 한다
            sock = getattr(getattr(getattr(hold.get('resp'), 'fp', None), 'raw', None), '_sock', None)
            if sock is not None and not finished:
                sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        shutil.rmtree(job_files_dir(job), ignore_errors=True)
    sec = round(time.time() - t0)
    a = ''.join(answer).strip()
    gen = time.time() - (t_first or t0)
    out.update(sec=sec, usedModel=f'{name} · {len(a) / max(0.1, gen):.0f}자/초' if a else name,
               progress=f'{name} · 생각 {len("".join(reason)):,}자 · 답 {len(a):,}자')
    if canceled:
        return dict(out, sessionId=job.get('sessionId') or '', result='', error='', canceled=True)
    if not a:
        why = err or ('생각만 하다 답을 못 냈어요. 질문을 줄이거나 빠른 모델로 다시 보내 주세요.' if reason else '로컬 LLM 이 빈 답을 보냈어요.')
        return dict(out, sessionId=job.get('sessionId') or '', result='', error=why)
    note = f'[사진 {len(paths)}장]\n' if paths else ''
    local_save(sid, local_trim(hist + [{'role': 'user', 'content': note + text}, {'role': 'assistant', 'content': a}]))
    if err:
        a += '\n\n(' + err + ' 여기까지만 받았어요.)'
    elif hold.get('length'):
        a += '\n\n(모델이 한 번에 다룰 수 있는 양이 차서 답이 여기서 끊겼어요. "계속"이라고 보내거나, 계속 끊기면 새 대화로 시작해 주세요.)'
    return dict(out, result=a[:60000], error='')


PENDING = os.path.join(INBOX, 'pending-done')   # 못 보낸 결과(워커 키는 빼고 저장)
DONE_FATAL = ('not_found', 'bad_key', 'bad_json', 'too_big')   # 다시 보내도 소용없는 거절


def post_done(body):
    """rcDone 한 번. 'ok'(반영됨)·'fatal'(다시 보내도 소용없음)·'retry'(끊김·서버 일시 오류) 중 하나.
    Worker 는 내부 오류도 HTTP 200 + ok:false('server') 로 돌려주므로 응답의 ok 를 꼭 본다."""
    try:
        r = post(dict(body, action='rcDone', key=KEY), timeout=30)
    except Exception as e:
        print(time.strftime('%Y-%m-%d %H:%M:%S'), '결과 보내기 실패', body.get('id'), e, flush=True)
        return 'retry'
    if r.get('ok'):
        return 'ok'
    print(time.strftime('%Y-%m-%d %H:%M:%S'), '결과 거절', body.get('id'), r.get('error'), flush=True)
    return 'fatal' if r.get('error') in DONE_FATAL else 'retry'


def send_done(body):
    """결과 보내기. 실패하면 5초 뒤 한 번 더, 그래도 안 되면 파일로 두었다가 다음 확인 때 다시 보낸다
    (안 그러면 결과가 사라지고 30분 뒤 'PC 응답 없음' 오류로 바뀜. 서버는 끝난 요청을 덮어쓰지 않으므로 재전송해도 안전).
    오래 붙잡지 않는 이유: 그동안 rcTake 를 못 불러 사이트에 'PC 꺼짐'으로 보이고 다른 요청도 멈춤."""
    for wait in (0, 5):
        time.sleep(wait)
        st = post_done(body)
        if st != 'retry':
            return st == 'ok'
    os.makedirs(PENDING, exist_ok=True)
    fp = os.path.join(PENDING, body['id'] + '.json')
    with open(fp + '.tmp', 'w', encoding='utf-8') as f:   # 임시 이름에 다 쓴 뒤 바꿔야 반쯤 쓰인 파일이 안 생김
        json.dump(body, f, ensure_ascii=False)
    os.replace(fp + '.tmp', fp)
    return False


def session_cwd(sid):
    """그 세션이 실행된 폴더(세션 기록 첫 줄들의 cwd). 세션 파일이 없으면 None."""
    hits = glob.glob(os.path.join(os.path.expanduser('~'), '.claude', 'projects', '*', sid + '.jsonl'))
    for fp in hits:
        try:
            with open(fp, encoding='utf-8') as f:
                for _, line in zip(range(40), f):
                    cwd = (json.loads(line) or {}).get('cwd') if '"cwd"' in line else None
                    if cwd:
                        return cwd
        except (OSError, ValueError):
            continue
    return None


def inside(path, base):
    path, base = os.path.normcase(os.path.realpath(path)), os.path.normcase(os.path.realpath(base))
    return path == base or path.startswith(base.rstrip('\\/') + os.sep)


def open_in_app(job):
    """'Claude 앱으로 보내기': 이 대화의 마지막 세션을 복사(--fork-session)해 원격 연결(--remote-control)을 켠
    Claude Code 창을 PC 에 새로 띄운다. Claude 는 -p 로 돌리지 않고, 창은 다리와 따로 살아 있다(창을 닫으면 원격 연결도 꺼짐).
    복사본이라 원래 대화(사이트)와 앱 쪽이 같은 세션 파일을 동시에 고치지 않는다."""
    t0 = time.time()
    sid = str(job.get('sessionId') or '')
    if not sid or not all(c.isalnum() or c == '-' for c in sid):
        return {'result': '', 'error': '이 대화에 이어 갈 Claude 세션이 없어요. 요청을 한 번 끝까지 실행한 뒤 다시 보내 주세요.', 'sec': 0}
    cwd = session_cwd(sid)
    if not cwd or not os.path.isdir(cwd):
        return {'result': '', 'error': 'PC 에서 이 대화의 세션 기록을 찾지 못했어요(지워졌거나 다른 PC 에서 실행한 대화).', 'sec': 0}
    if not (inside(cwd, ROOT) or inside(cwd, INBOX)):   # 다리 작업 폴더 밖에서 연 세션은 열지 않는다
        return {'result': '', 'error': '이 대화의 세션이 작업 폴더 밖에 있어 열지 않았어요.', 'sec': 0}
    title = ''.join(c for c in str(job.get('title') or '대화') if c.isprintable())   # 제어 문자(NUL 등)는 실행 인자에 못 넣으므로 뺀다
    name = ' '.join(('원격: ' + title).split())[:50]
    cmd = [claude_exe(), '--resume', sid, '--fork-session', '--remote-control', name]
    flags = getattr(subprocess, 'CREATE_NEW_CONSOLE', 0) | getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)
    try:
        p = subprocess.Popen(cmd, cwd=cwd, env=child_env(), creationflags=flags, close_fds=True)
    except OSError as e:
        return {'result': '', 'error': f'Claude Code 창을 열지 못했어요: {e}'[:300], 'sec': 0}
    for _ in range(16):   # 곧바로 꺼지면(세션 없음·로그인 필요 등) 실패로 알린다
        if p.poll() is not None:
            return {'result': '', 'error': f'Claude Code 창이 바로 닫혔어요(종료 코드 {p.returncode}). PC 에서 claude 로그인 상태를 확인해 주세요.', 'sec': round(time.time() - t0)}
        time.sleep(0.5)
    where = os.path.relpath(cwd, ROOT) if inside(cwd, ROOT) else cwd
    return {'result': (f"PC 에 원격 연결을 켠 Claude Code 창을 열었어요.\n\n"
                       f"- Claude 앱(또는 claude.ai/code)의 **Code** 목록에서 **{name}** 을(를) 찾아 이어서 쓰면 돼요.\n"
                       f"- 이 대화를 복사해서 연 거라, 여기 대화는 그대로 남고 앱 쪽은 따로 이어져요.\n"
                       f"- 작업 폴더: `{where}` · PC 의 그 창을 닫으면 원격 연결도 꺼져요.\n"
                       f"- ⚠ 앱 쪽 창은 PC 에 로그인된 Claude 계정으로만 조종되고, 이 사이트의 보호 장치(위험 명령 막기·작업 폴더 제한·명령 끔)가 걸리지 않아요. "
                       f"그 폴더의 프로젝트 설정에 따라 배포·삭제 같은 명령도 묻지 않고 실행될 수 있으니 앱에서 시킬 때 조심하세요."),
            'sec': round(time.time() - t0), 'sessionId': sid}


def flush_pending():
    """예전에 못 보낸 결과를 다시 보낸다. 끊김·일시 오류면 다음 확인으로 미루고, 깨진 파일은 .bad 로 치워 뒤를 막지 않는다."""
    for fp in sorted(glob.glob(os.path.join(PENDING, '*.json'))):
        try:
            with open(fp, encoding='utf-8') as f:
                body = json.load(f)
        except Exception as e:
            print(time.strftime('%Y-%m-%d %H:%M:%S'), '밀린 결과 파일 깨짐', os.path.basename(fp), e, flush=True)
            os.replace(fp, fp + '.bad')
            continue
        st = post_done(body)
        if st == 'retry':
            return
        os.remove(fp)
        print(time.strftime('%Y-%m-%d %H:%M:%S'), '밀린 결과 보냄' if st == 'ok' else '밀린 결과 버림(서버 거절)', body.get('id'), flush=True)


FOLDERS_SENT = [None, 0.0]
KEY_BACKOFF = [0.0]   # 서버가 연결 코드를 거절(bad_key)하면 10분 동안 확인을 쉰다(취소된 코드로 15초마다 두드리지 않게)
LLM_SENT, LLM_CHK = [None, 0.0], [None, 0.0]   # 로컬 LLM 상태: 마지막으로 보낸 값·시각 / 마지막 확인 값·시각
BOOT = False   # 계속 실행할 때만 True: 첫 확인에서 서버가 '실행 중'으로 남은 옛 요청(다리가 꺼지며 끊긴 것)을 정리한다


def take():
    """서버에서 요청 하나 받기(없으면 None). 같은 대화의 요청은 서버가 앞 요청이 끝난 뒤에만 넘긴다."""
    global BOOT
    if time.time() < KEY_BACKOFF[0]:
        return None
    flush_pending()
    body = {'action': 'rcTake', 'key': KEY, 'boot': BOOT, 'dir': ROOT, 'pc': socket.gethostname()[:40], 'v': BRIDGE_V}
    folders = folder_list()
    if BOOT or folders != FOLDERS_SENT[0] or time.time() - FOLDERS_SENT[1] > 600:   # 켜질 때·바뀔 때·10분마다
        body['folders'] = folders
    now = time.time()
    if BOOT or now - LLM_CHK[1] > 60:   # 로컬 LLM 상태는 1분마다 확인, 바뀌었거나 10분 지나면 보냄
        LLM_CHK[0], LLM_CHK[1] = local_status(), now
    if BOOT or LLM_CHK[0] != LLM_SENT[0] or now - LLM_SENT[1] > 600:
        body['llm'] = LLM_CHK[0]
    r = post(body)
    if 'folders' in body:
        FOLDERS_SENT[:] = [folders, time.time()]
    if 'llm' in body:
        LLM_SENT[:] = [body['llm'], now]
    BOOT = False
    if r.get('error') == 'bad_key':   # 연결 코드가 취소됐거나(허용 끔·새 코드 발급) 워커 키가 바뀜 → 기록에 남기고 10분 쉼
        KEY_BACKOFF[0] = time.time() + 600
        print(time.strftime('%Y-%m-%d %H:%M:%S'), '서버가 연결 코드를 거절함(bad_key) — 사이트에서 연결 코드를 다시 만들었거나 허용이 꺼졌어요. 10분 뒤 다시 확인', flush=True)
        return None
    if not r.get('ok') or not r.get('job'):
        return None
    job = r['job']
    print(time.strftime('%Y-%m-%d %H:%M:%S'), '받음', job['id'], job.get('model') or '기본', job.get('mode') or '수정 허용',
          job['prompt'][:60].replace('\n', ' '), flush=True)
    return job


def handle(job):
    """받은 요청 하나를 실행하고 결과를 보낸다(스레드마다 하나씩 동시에 돌 수 있음: 요청마다 임시 폴더·보호 장치 기록이 따로)."""
    claim = dir_claim(job)
    if claim and not wait_dirs(job, claim):
        res, claim = {'result': '', 'error': '', 'sec': 0, 'canceled': True}, None
    else:
        try:
            res = ({'result': '', 'error': '이 PC 는 잠금 다리라 Claude 앱으로 보내기를 쓸 수 없어요.', 'sec': 0} if job.get('mode') == 'open' and LOCKED else
                   open_in_app(job) if job.get('mode') == 'open' else run_local(job) if job.get('model') in LOCAL_MODELS else
                   {'result': '', 'error': '이 다리가 모르는 로컬 모델이에요. 다리를 업데이트해 주세요.', 'sec': 0} if str(job.get('model') or '').startswith('local-') else run(job))
        except Exception as e:
            res = {'result': '', 'error': f'PC 다리 오류: {e}'[:300], 'sec': 0}
        finally:
            if claim:
                dir_release(claim)
    try:
        sent = send_done({'id': job['id'], **res})
    except Exception as e:   # 결과 파일도 못 남기면 기록만(스레드가 조용히 죽지 않게)
        sent = False
        print(time.strftime('%Y-%m-%d %H:%M:%S'), '결과 보내기 오류', job['id'], e, flush=True)
    state = '중지됨' if res.get('canceled') else ('오류: ' + res['error'] if res.get('error') else '완료')
    print(time.strftime('%Y-%m-%d %H:%M:%S'), '보냄' if sent else '보내기 미룸', job['id'], f"{res.get('sec', 0)}초", state, flush=True)


def once():
    job = take()
    if not job:
        return False
    handle(job)
    return True


def install():
    """로그인하면 창 없이 자동 실행(시작프로그램 바로가기) + 지금 바로 켜기. Windows 전용."""
    pyw = os.path.join(os.path.dirname(sys.executable), 'pythonw.exe')
    pyw = pyw if os.path.exists(pyw) else sys.executable
    lnk = os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', LNK_NAME)
    q = lambda s: s.replace("'", "''")
    ps = (f"$s=(New-Object -ComObject WScript.Shell).CreateShortcut('{q(lnk)}');$s.TargetPath='{q(pyw)}';"
          f"$s.Arguments='\"{q(os.path.abspath(__file__))}\"';$s.WorkingDirectory='{q(HERE)}';$s.Description='원격 Claude 다리';$s.Save()")
    subprocess.run(['powershell', '-NoProfile', '-Command', ps], check=True, creationflags=NO_WINDOW)
    subprocess.Popen([pyw, os.path.abspath(__file__)], cwd=HERE, creationflags=NO_WINDOW | getattr(subprocess, 'DETACHED_PROCESS', 0))
    print('자동 실행을 켰어요. 이제 PC에 로그인하면 창 없이 켜지고, 지금도 켰어요.\n기록: ' + os.path.join(HERE, 'remote_claude.log'))


if __name__ == '__main__':
    if not KEY:
        print('연결 코드가 없어요. 원격 Claude 사이트 → 설정 → "내 PC 연결"에서 코드를 만든 뒤 다시 실행하면 연결 코드를 물어요:\n'
              '  python remote_claude.py --dir <Claude 가 일할 폴더>')
        sys.exit(1)
    if not os.path.isdir(ROOT):
        print('작업 폴더가 없어요:', ROOT, '\n  python remote_claude.py --dir <있는 폴더> 로 다시 정하세요.'); sys.exit(1)
    if locked_problem():
        print('잠금 다리를 시작하지 않았어요:', locked_problem()); sys.exit(1)
    if '--install' in sys.argv:
        install(); sys.exit(0)
    if '--once' in sys.argv:
        once(); sys.exit(0)
    lock = socket.socket()
    try:
        lock.bind(('127.0.0.1', LOCK_PORT))   # 다리 폴더마다 하나만 실행(프로세스가 끝나면 자동으로 풀림)
    except OSError:
        print('이미 실행 중입니다.'); sys.exit(0)
    if sys.stdout is None:   # pythonw(창 없음): 기록을 파일로
        lp = os.path.join(HERE, 'remote_claude.log')
        if os.path.isfile(lp) and os.path.getsize(lp) > 2_000_000:   # 2MB 넘으면 하나만 남기고 돌림(.log.old)
            try: os.replace(lp, lp + '.old')
            except OSError: pass   # 다른 프로그램이 열고 있으면 이번엔 돌리지 않고 이어 씀(시작은 막지 않음)
        sys.stdout = sys.stderr = open(lp, 'a', encoding='utf-8', buffering=1)
    print(time.strftime('%Y-%m-%d %H:%M:%S'), '원격 Claude 다리 시작:', API, '·', claude_exe(), '· 작업 폴더', ROOT,
          '· 잠금(작업 폴더 밖·명령·위험 허용·웹 읽기 막음)' if LOCKED else '', '· 포트', LOCK_PORT, flush=True)
    if not LEGACY_MODE and sys.stdout.isatty():
        print('이 창을 닫으면 멈춰요. 자동으로 켜려면: python remote_claude.py --install', flush=True)
    BOOT = True
    idle_since = time.time()
    busy = []   # 실행 중인 요청 스레드(최대 MAX_PAR 개 동시, 2026-10-14)
    print(time.strftime('%Y-%m-%d %H:%M:%S'), f'동시 실행 최대 {MAX_PAR}개', flush=True)
    while True:
        busy = [t for t in busy if t.is_alive()]
        if os.path.exists(DRAIN):   # 재시작 준비: 새 요청은 받지 않고, 다 끝나면 끈다
            if not busy:
                try:
                    flush_pending()
                finally:
                    os.remove(DRAIN)
                print(time.strftime('%Y-%m-%d %H:%M:%S'), '실행 중인 요청이 모두 끝나 다리를 끕니다(재시작)', flush=True)
                sys.exit(0)
            time.sleep(POLL_S); continue
        try:
            if len(busy) - len(WAITING) < MAX_PAR and len(busy) < MAX_PAR * 2:   # 폴더를 기다리는 요청은 자리를 차지하지 않음(모두 합쳐 6개까지)
                job = take()
                if job:
                    th = threading.Thread(target=handle, args=(job,), daemon=True)
                    th.start(); busy.append(th)
                    idle_since = time.time()
                    continue   # 바로 하나 더 받을 수 있는지 확인
        except Exception as e:
            print(time.strftime('%Y-%m-%d %H:%M:%S'), '오류', e, flush=True)
        # 실행 중이거나 2분 안에 받았으면 5초, 아니면 15초마다(서버 무료 한도 아끼기)
        time.sleep(POLL_S if busy or time.time() - idle_since < 120 else IDLE_POLL_S)
