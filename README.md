# Claude Code Security Analysis Handbook

Companion labs for **터미널에서 시작하는 보안 분석 — Claude Code 실무 핸드북** by Juwon Bang.
Practice investigating synthetic logs, checking model claims against source evidence, and protecting investigation inputs.

## Start the labs

Manuscript **v1.9** uses lab bundle **v0.3.2**. Manuscript and lab versions are separate.

1. Download **handbook-lab-files-v0.3.2.zip** from the [v0.3.2 release](https://github.com/Juwon1405/claude-code-security-handbook/releases/tag/v0.3.2), not GitHub's automatic Source code ZIP.
2. Follow the [Korean setup guide](lab/README.md#처음-설치하기) in a new lab folder and verify the included checksums.
3. Generate the synthetic data, then follow the chapters in order. Install the examples under `examples/ch15/` only when chapter 15 asks for them.

The reference platform is Apple Silicon macOS. Selected offline exercises also run on Ubuntu ARM64. See the book's appendix D for Windows/WSL2 preparation and the release notes for verification limits.

For manuscripts v1.7–v1.8, v0.3.2 retains the same exercise files as the private v0.3.1 bundle; only the README and its checksum changed. For manuscript v1.5, use the preserved [v0.2.1 release](https://github.com/Juwon1405/claude-code-security-handbook/releases/tag/v0.2.1).

## Author and feedback

Juwon's earlier book, [보안 실무자를 위한 네트워크 공격 패킷 분석](https://www.yes24.com/product/goods/83538369), covers recognizing abnormal traffic through protocol analysis.

[Lab guide](lab/README.md) · [Use and sharing terms](lab/README.md#사용과-공유) · [Report an issue](https://github.com/Juwon1405/claude-code-security-handbook/issues)

Use only the supplied synthetic data. Include the version, platform, chapter, and reproduction steps in an issue; do not upload incident evidence, account details, or credentials. The manuscript PDF and Word files are not distributed in this repository.
