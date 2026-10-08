# -*- coding: utf-8 -*-
"""원격 Claude 다리: 원격 Claude 사이트(시험지 관리자 계정으로 로그인)에서 보낸 요청을
이 PC 의 Claude Code 로 실행하고 결과를 서버에 돌려준다.

  python tools/remote_claude.py            # 계속 실행(5초마다 확인). 끄려면 Ctrl+C
  python tools/remote_claude.py --once     # 한 번만 확인
  pythonw tools/remote_claude.py           # 창 없이(시작프로그램 바로가기가 이렇게 켬). 기록은 tools/remote_claude.log

- 이미 켜져 있으면 두 번째는 바로 끝난다(127.0.0.1:47213 포트로 확인).
- PC 는 서버로 나가는 요청만 한다(포트를 열지 않음). 인증은 study-helper/sync.json 의 key(워커 키).
- 작업 폴더는 D:\\AI_HEO, 한 요청당 최대 20분·40턴. 같은 대화(thread)의 요청은 서버가 준 sessionId 로 이어 간다.
- 실행 중에는 몇 초마다 작업 기록(읽은 파일·실행한 명령)을 서버에 보내고, 사이트에서 '중지'를 누르면 Claude 를 끈다.
- 서버 주소는 sync.json 의 url(Cloudflare Worker).
- 요청에 사진이 붙어 있으면 remote-claude-inbox 폴더에 저장하고, 그 경로를 요청 앞에 적어 Claude 가 Read 로 보게 한다.
"""
import base64, glob, json, os, queue, shutil, socket, subprocess, sys, threading, time, urllib.request

# 두 가지로 쓴다
#  - 관리자 PC(D:\AI_HEO\tools): study-helper/sync.json 의 워커 키로 관리자 계정 요청을 받고, 작업 폴더는 D:\AI_HEO
#  - 다른 사람 PC: 사이트 설정 '내 PC 연결'에서 받은 연결 코드로 그 사람 요청만 받는다.
#      python remote_claude.py --key <연결 코드> --dir <작업 폴더>   (처음 한 번. 옆의 remote_claude.json 에 저장)
#      python remote_claude.py --install                            (로그인하면 자동 실행 + 지금 켜기)
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_API = 'https://exam-api.dawn-sea-4052.workers.dev'
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
        except Exception:
            conf = {}
    changed = False
    for k, flag in (('key', '--key'), ('dir', '--dir'), ('url', '--url')):
        v = arg(flag)
        if v:
            conf[k] = os.path.abspath(v) if k == 'dir' else v.strip()
            changed = True
    # 다른 사람 PC 처음 실행: 연결 코드를 명령줄에 쓰면 PowerShell 기록에 남으므로 여기서 묻는다(입력이 화면에 안 보임)
    if not conf.get('key') and not os.path.exists(LEGACY) and __name__ == '__main__' and sys.stdin and sys.stdin.isatty():
        import getpass
        k = getpass.getpass('원격 Claude 사이트의 연결 코드를 붙여 넣고 Enter (화면에 안 보여요): ').strip()
        if k:
            conf['key'] = k
            changed = True
    if changed:
        with open(CONF, 'w', encoding='utf-8') as f:
            json.dump(conf, f, ensure_ascii=False, indent=2)
    if conf.get('key'):
        return conf.get('url') or DEFAULT_API, conf['key'], os.path.abspath(conf.get('dir') or HERE), False
    if os.path.exists(LEGACY):
        c = json.load(open(LEGACY, encoding='utf-8'))
        return c.get('url') or DEFAULT_API, c['key'], os.path.dirname(HERE), True
    return DEFAULT_API, '', HERE, False


API, KEY, ROOT, LEGACY_MODE = load_conf(sys.argv)
TIMEOUT_S = 20 * 60
INBOX = os.path.join(ROOT, 'remote-claude-inbox')
EXT = {'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp', 'image/gif': 'gif'}
POLL_S = 5
IDLE_POLL_S = 15
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
    drop = ('ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'CLAUDECODE') if LEGACY_MODE else ('CLAUDECODE',)   # 다른 사람 PC 는 API 키로 쓸 수도 있어 그대로 둠
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


def save_files(job):
    """사진을 받아 INBOX 에 저장하고 경로 목록을 돌려준다(받지 못한 사진은 건너뜀)."""
    paths = []
    for i, fid in enumerate(job.get('files') or []):
        try:
            r = post({'action': 'rcFile', 'key': KEY, 'id': fid}, timeout=60)
            head, b64 = r['data'].split(',', 1)
            os.makedirs(INBOX, exist_ok=True)
            path = os.path.join(INBOX, f"{job['id']}_{i + 1}.{EXT.get(head[5:].split(';')[0], 'jpg')}")
            with open(path, 'wb') as fp:
                fp.write(base64.b64decode(b64))
            paths.append(path)
        except Exception as e:
            print(time.strftime('%H:%M:%S'), '사진 받기 실패', fid, e, flush=True)
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
    """원격 요청에만 붙이는 위험 명령 막기 훅(tools/rc_guard.py). 평소 Claude Code 사용에는 영향 없음."""
    return json.dumps({'hooks': {'PreToolUse': [{'matcher': '*', 'hooks': [{'type': 'command', 'command': f'"{console_python()}" "{GUARD}"', 'timeout': 30}]}]}})


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
    """보호 장치가 이 PC 에서 실제로 막는지 요청마다 확인(파일 없음·깨짐·파이썬 문제면 bypassPermissions 로 그냥 실행되므로)."""
    sample = json.dumps({'tool_name': 'Bash', 'tool_input': {'command': 'git push origin main  # 한글 확인'}}, ensure_ascii=False).encode('utf-8')
    if not os.path.isfile(GUARD):
        return False
    try:
        r = subprocess.run([console_python(), GUARD], input=sample, capture_output=True, timeout=30, creationflags=NO_WINDOW,
                           env=dict(child_env(), RC_ALLOW_DANGER='0', RC_GUARD_LOG='', RC_ROOT=ROOT))   # 실제 실행과 같은 환경
        # 파이썬의 '파일 없음'도 종료 코드 2 라서, 보호 장치가 직접 쓴 표시까지 확인한다
        return r.returncode == 2 and b'[rc_guard]' in r.stderr
    except Exception:
        return False


def run(job):
    if not guard_works():
        return {'result': '', 'error': 'PC 의 보호 장치(rc_guard.py)가 동작하지 않아 실행하지 않았어요. 다리 폴더에 rc_guard.py 가 있는지 확인하세요.', 'sec': 0}
    prompt = with_files(job['prompt'], save_files(job))
    if prompt.startswith('-'):
        prompt = ' ' + prompt   # '-' 로 시작하면 claude 가 옵션으로 읽지 않게
    cmd = [claude_exe(), '-p', prompt, '--output-format', 'stream-json', '--verbose', '--max-turns', '40',
           '--settings', guard_settings()]
    guard_log = os.path.join(os.environ.get('TEMP', ROOT), f"rc_guard_{job.get('id', 'x')}.jsonl")
    try:
        os.remove(guard_log)
    except OSError:
        pass
    env = dict(child_env(), RC_GUARD_LOG=guard_log, RC_ALLOW_DANGER='1' if job.get('allow') else '0', RC_ROOT=ROOT)
    guard_seen, danger = 0, []
    if job.get('model') in ('sonnet', 'opus', 'fable', 'haiku'):
        cmd += ['--model', job['model']]
    # 읽기만 = plan(파일을 고치지 않음). 아니면 묻지 않고 실행하되 위험한 명령은 위의 훅(rc_guard)이 막는다
    cmd += ['--permission-mode', 'plan' if job.get('mode') == 'plan' else 'bypassPermissions']
    if job.get('title'):
        cmd += ['-n', '원격: ' + ' '.join(job['title'].split())[:40]]
    if job.get('sessionId'):
        cmd += ['--resume', job['sessionId']]
    t0 = time.time()
    p = subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, creationflags=NO_WINDOW)
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
        if now - t0 > TIMEOUT_S:
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
    skipped = f'… 앞의 {len(log) - 40}단계 생략\n' if len(log) > 40 else ''
    out = {'sessionId': final.get('session_id') or st['session'], 'sec': sec, 'progress': (skipped + '\n'.join(log[-40:]))[:4000],
           'usedModel': st['model'], 'turns': final.get('num_turns') or 0, 'danger': '\n'.join(danger)[:2000]}
    if canceled:
        return dict(out, result='', error='', canceled=True)
    if timed_out:
        return dict(out, result='', error=f'{TIMEOUT_S // 60}분 안에 끝나지 않아 멈췄습니다.')
    if not final:
        msg = (b''.join(err).decode('utf-8', 'replace').strip() or f'결과 없이 끝났습니다(종료 코드 {p.returncode}).')
        return dict(out, result=msg[:60000], error=msg[:300])
    result = str(final.get('result') or '')
    sub = final.get('subtype')
    is_err = bool(final.get('is_error')) or sub not in (None, 'success')
    why = {'error_max_turns': '40턴 안에 끝내지 못했습니다. 요청을 나눠서 보내 주세요.'}.get(sub, str(sub))
    return dict(out, result=result[:60000] or (why if is_err else ''), error=(result[:300] or why) if is_err else '')


PENDING = os.path.join(INBOX, 'pending-done')   # 못 보낸 결과(워커 키는 빼고 저장)
DONE_FATAL = ('not_found', 'bad_key', 'bad_json', 'too_big')   # 다시 보내도 소용없는 거절


def post_done(body):
    """rcDone 한 번. 'ok'(반영됨)·'fatal'(다시 보내도 소용없음)·'retry'(끊김·서버 일시 오류) 중 하나.
    Worker 는 내부 오류도 HTTP 200 + ok:false('server') 로 돌려주므로 응답의 ok 를 꼭 본다."""
    try:
        r = post(dict(body, action='rcDone', key=KEY), timeout=30)
    except Exception as e:
        print(time.strftime('%H:%M:%S'), '결과 보내기 실패', body.get('id'), e, flush=True)
        return 'retry'
    if r.get('ok'):
        return 'ok'
    print(time.strftime('%H:%M:%S'), '결과 거절', body.get('id'), r.get('error'), flush=True)
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


def flush_pending():
    """예전에 못 보낸 결과를 다시 보낸다. 끊김·일시 오류면 다음 확인으로 미루고, 깨진 파일은 .bad 로 치워 뒤를 막지 않는다."""
    for fp in sorted(glob.glob(os.path.join(PENDING, '*.json'))):
        try:
            with open(fp, encoding='utf-8') as f:
                body = json.load(f)
        except Exception as e:
            print(time.strftime('%H:%M:%S'), '밀린 결과 파일 깨짐', os.path.basename(fp), e, flush=True)
            os.replace(fp, fp + '.bad')
            continue
        st = post_done(body)
        if st == 'retry':
            return
        os.remove(fp)
        print(time.strftime('%H:%M:%S'), '밀린 결과 보냄' if st == 'ok' else '밀린 결과 버림(서버 거절)', body.get('id'), flush=True)


BOOT = False   # 계속 실행할 때만 True: 첫 확인에서 서버가 '실행 중'으로 남은 옛 요청(다리가 꺼지며 끊긴 것)을 정리한다


def once():
    global BOOT
    flush_pending()
    r = post({'action': 'rcTake', 'key': KEY, 'boot': BOOT, 'dir': ROOT, 'pc': socket.gethostname()[:40]})
    BOOT = False
    if not r.get('ok') or not r.get('job'):
        return False
    job = r['job']
    print(time.strftime('%H:%M:%S'), '받음', job['id'], job.get('model') or '기본', job.get('mode') or '수정 허용',
          job['prompt'][:60].replace('\n', ' '), flush=True)
    try:
        res = run(job)
    except Exception as e:
        res = {'result': '', 'error': f'PC 다리 오류: {e}'[:300], 'sec': 0}
    sent = send_done({'id': job['id'], **res})
    state = '중지됨' if res.get('canceled') else ('오류: ' + res['error'] if res.get('error') else '완료')
    print(time.strftime('%H:%M:%S'), '보냄' if sent else '보내기 미룸', job['id'], f"{res.get('sec', 0)}초", state, flush=True)
    return True


def install():
    """로그인하면 창 없이 자동 실행(시작프로그램 바로가기) + 지금 바로 켜기. Windows 전용."""
    pyw = os.path.join(os.path.dirname(sys.executable), 'pythonw.exe')
    pyw = pyw if os.path.exists(pyw) else sys.executable
    lnk = os.path.join(os.environ.get('APPDATA', ''), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup', '원격 Claude 다리.lnk')
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
    if '--install' in sys.argv:
        install(); sys.exit(0)
    if '--once' in sys.argv:
        once(); sys.exit(0)
    lock = socket.socket()
    try:
        lock.bind(('127.0.0.1', 47213))   # 하나만 실행(프로세스가 끝나면 자동으로 풀림)
    except OSError:
        print('이미 실행 중입니다.'); sys.exit(0)
    if sys.stdout is None:   # pythonw(창 없음): 기록을 파일로
        sys.stdout = sys.stderr = open(os.path.join(HERE, 'remote_claude.log'), 'a', encoding='utf-8', buffering=1)
    print('원격 Claude 다리 시작:', API, '·', claude_exe(), '· 작업 폴더', ROOT, flush=True)
    if not LEGACY_MODE and sys.stdout.isatty():
        print('이 창을 닫으면 멈춰요. 자동으로 켜려면: python remote_claude.py --install', flush=True)
    BOOT = True
    idle_since = time.time()
    while True:
        try:
            if once():
                idle_since = time.time()
                continue
        except Exception as e:
            print(time.strftime('%H:%M:%S'), '오류', e, flush=True)
        # 2분 넘게 할 일이 없으면 15초마다(서버 무료 한도 아끼기). 요청을 받으면 다시 5초
        time.sleep(POLL_S if time.time() - idle_since < 120 else IDLE_POLL_S)
