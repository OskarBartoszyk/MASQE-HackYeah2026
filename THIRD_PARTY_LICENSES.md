# Third-party components

All runtime dependencies are open source and permit use, modification and
redistribution in this project. Versions are those pinned in `go.sum`,
`ai-guard/requirements.txt` and `dashboard/package-lock.json`.

## Gateway (Go)

| Component | Version | License |
| --- | --- | --- |
| github.com/mattn/go-sqlite3 (bundles SQLite, public domain) | 1.14.24 | MIT |
| gopkg.in/yaml.v3 | 3.0.1 | MIT and Apache-2.0 |
| Go standard library | 1.23+ | BSD-3-Clause |

## AI Guard and SDK (Python)

| Component | Version | License |
| --- | --- | --- |
| scikit-learn | 1.6.1 | BSD-3-Clause |
| numpy, scipy, joblib, threadpoolctl (scikit-learn dependencies) | — | BSD-3-Clause |
| Python standard library | 3.10+ | PSF License |

The SDK (`sdk/python`) and the MCP proxy use the standard library only.

## Dashboard (JavaScript)

| Component | Version | License |
| --- | --- | --- |
| react, react-dom, scheduler | 19.3.0 | MIT |
| vite, rolldown, @vitejs/plugin-react, postcss, nanoid, fdir, picomatch, tinyglobby | — | MIT |
| picocolors | 1.1.1 | ISC |
| source-map-js | 1.2.2 | BSD-3-Clause |
| detect-libc | 2.1.2 | Apache-2.0 |
| lightningcss (build-time CSS minifier, not shipped in source form) | 1.33.0 | MPL-2.0 |

## Models and runtimes (not redistributed; downloaded by the user)

| Component | License |
| --- | --- |
| Ollama | MIT |
| Gemma 3 (`gemma3:4b`) | Gemma Terms of Use (not an OSI license; permits commercial use under its terms) |
| Llama 3.2 (`llama3.2`) | Llama 3.2 Community License |
| Mistral 7B (`mistral`) | Apache-2.0 |

No model weights, datasets or paid-API keys are included in this repository.
