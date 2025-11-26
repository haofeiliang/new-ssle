@echo off

rem 你的项目路径
set proj=E:\Codes\new-ssle

cargo build -r --package network2 --example tcp_share

rem 打开 Windows Terminal，创建一个 tab，然后在里面分成 4 个 pane
wt ^
  new-tab -d "%proj%" pwsh -NoExit -Command "./target/release/examples/tcp_share.exe -c './config.txt' -p 4 -i 0" ^
  ; split-pane -H -d "%proj%" pwsh -NoExit -Command "./target/release/examples/tcp_share.exe -c './config.txt' -p 4 -i 1" ^
  ; split-pane -V -d "%proj%" pwsh -NoExit -Command "./target/release/examples/tcp_share.exe -c './config.txt' -p 4 -i 2" ^
  ; focus-pane -t 0 ^
  ; split-pane -V -d "%proj%" pwsh -NoExit -Command "./target/release/examples/tcp_share.exe -c './config.txt' -p 4 -i 3"
