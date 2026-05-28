"""wave Dispatch CLI — `dispatch serve` runs the local-first proxy. Installed by `pip install wave-dispatch`."""
import sys


def main():
    args = sys.argv[1:]
    if args and args[0] == "serve":
        from . import proxy
        proxy.serve()
        return
    print(
        "wave Dispatch — https://dispatch.wave.online\n"
        "\n"
        "  dispatch serve     run the local-first OpenAI-compatible proxy on :8090\n"
        "                     point your agent at it:  OPENAI_BASE_URL=http://localhost:8090/v1\n"
        "\n"
        "  env:\n"
        "    WAVE_LICENSE=wv_...        use the hosted classifier (else a local trivial-only heuristic)\n"
        "    WAVE_ENDPOINT=http://...   your Ollama / OpenAI-compatible local server (default :11434)\n"
        "    WAVE_OAI_UPSTREAM=https://api.openai.com   your frontier (escalation target)\n"
        "    WAVE_PROXY_LOCAL_MODEL=qwen2.5:3b-instruct\n"
        "\n"
        "  SDK:   from wave_dispatch import Dispatch; Dispatch().route('...')\n"
    )
    if args:                    # CR/#3: unknown command -> POSIX misuse exit code (was silent 0)
        sys.exit(2)
