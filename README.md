```markdown
# pwntools-qemu-debug-by-tmux

**Apple Silicon CTF유저를 위한 x86_64 바이너리 pwntools 디버깅 스크립트**`
이 파이썬 스크립트는 `qemu-user-static`과 GDB_STUB을 활용하여 x86_64 바이너리를 디버깅할 수 있도록 도와주며, `pwntools`를 사용하여 pwn 챌린지를 효과적으로 해결할 수 있게 합니다. `tmux`를 통합하여 터미널 창을 자동으로 분할하고, 바이너리와 GDB를 동시에 사용할 수 있는 환경을 제공합니다.

**Made for Apple Silicon CTF Users for Debugging x86_64 Binaries**
This Python script leverages `qemu-user-static` and GDB_STUB to facilitate debugging of x86_64 binaries, enabling you to tackle pwn challenges effectively using `pwntools`. By integrating `tmux`, the script automatically splits your terminal window, allowing simultaneous interaction with the binary and debugging through GDB.


## 주요 기능

- **자동 디버깅 설정**: QEMU를 GDB 서버 모드로 시작하고, 별도의 `tmux` 창에서 GDB를 실행합니다.
- **매끄러운 통합**: `pwntools`와 GDB를 동시에 사용하여 바이너리와 디버깅을 원활하게 수행할 수 있습니다.
- **Apple Silicon 호환**: Apple Silicon(M1/M2) 맥 사용자들을 위해 설계되었습니다.
- **효율적인 작업 흐름**: 터미널 창을 분할하여 인터랙티브 사용과 디버깅을 수동 설정 없이 자동으로 수행합니다.

## Features

- **Automated Debugging Setup**: Automatically starts QEMU in GDB server mode and launches GDB in a separate `tmux` pane.
- **Seamless Integration**: Allows simultaneous interaction with the binary and debugging using `pwntools` and GDB.
- **Apple Silicon Compatible**: Specifically designed for users running on Apple Silicon (M1/M2) Macs.
- **Efficient Workflow**: Split terminal panes for interactive use and debugging without manual setup.


## 사전 요구 사항

이 스크립트를 사용하기 전에 다음 도구들이 시스템에 설치되어 있어야 합니다:

- **tmux**: 터미널 멀티플렉서로, 터미널 창을 분할할 수 있습니다.
- **gdb-multiarch**: 여러 아키텍처를 지원하는 GDB 버전.
- **qemu-user-static**: 다른 아키텍처용 바이너리를 실행하기 위한 QEMU 유저 모드 에뮬레이션.
- **pwntools**: CTF 및 익스플로잇 개발을 위한 파이썬 라이브러리.

## Prerequisites

Before using this script, ensure that the following tools are installed on your system:

- **tmux**: Terminal multiplexer for splitting terminal windows.
- **gdb-multiarch**: GDB version that supports multiple architectures.
- **qemu-user-static**: QEMU user mode emulation for running binaries compiled for different architectures.
- **pwntools**: Python library for CTFs and exploit development.