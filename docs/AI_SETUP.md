# Configure optional AI

AI is optional. You can analyze binaries, explore code and inspect reference
matches without an AI provider. Configure AI when you want assistance with
unresolved functions or ambiguous candidates.

## Local Ollama

1. Install [Ollama for Windows](https://ollama.com/download/windows) and start it.
2. Open PowerShell and download the model used in the project's local tests:

```powershell
ollama pull qwen2.5-coder:7b
ollama list
```

3. Open the application's settings (`Paramètres`) and add an AI provider:

| Field | Value |
| --- | --- |
| Name | `Local Ollama` |
| Address | `http://localhost:11434/v1` |
| Model | `qwen2.5-coder:7b` |
| API key | Leave empty for the standard local Ollama server. |

4. Confirm that the provider is active, then run an AI analysis in the application.

The model name must match the installed name reported by `ollama list`.
To check the server independently, run:

```powershell
Invoke-RestMethod http://localhost:11434/api/tags
```

A response confirms that the server is reachable; it does not prove that a
complete naming request will succeed. Check the application's analysis status.

Model downloads and memory requirements are substantial. CPU/GPU, RAM/VRAM,
context size and function complexity affect response time. Increasing context
can increase memory use and latency; it does not guarantee better names.
Keep Ollama local rather than exposing it to your network for this setup.

## Remote provider

Add an OpenAI-compatible endpoint, its model name and the API key supplied by
that provider. Use the provider's documented endpoint and model identifiers.
Do not reuse the local Ollama address for a remote service.

Remote requests send selected analysis context, including pseudocode and
strings. Check authorization, provider policies and potential charges before
using confidential binaries. Keys are stored in local application settings,
not an encrypted credential vault. Do not share those settings.

## What to expect

AI can abstain, suggest a wrong name or return an unusable response. A semantic
fallback presented for manual review is not an automatic rename. More generated
names do not necessarily mean more correct names.

If a request fails, inspect the diagnostics, check the provider configuration
and retry the affected work. See [Troubleshooting](TROUBLESHOOTING.md).
