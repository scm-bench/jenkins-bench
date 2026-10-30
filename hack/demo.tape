# The animated demo at the top of the README: docs/demo.gif.
#
# Re-record it with vhs (https://github.com/charmbracelet/vhs) from the
# repository root whenever the sample or the report layout changes:
#
#   vhs hack/demo.tape
#
# It builds the binary from this checkout, so the recording always shows the
# code it ships with. The output is the real `scan --demo` report; the hidden
# wrapper only paces it line by line so it can be read as it scrolls past.

Output docs/demo.gif

Require go
Require script

Set Shell "bash"
Set FontSize 14
Set Width 1000
Set Height 600
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 60ms
Set Framerate 10
Set WindowBar Colorful

Set WaitTimeout 180s
Set WaitPattern /^\$ *$/

Hide
Type `export PS1='$ ' BIN=$(mktemp -d) && go build -o $BIN/jenkins-bench ./cmd/jenkins-bench`
Enter
Wait
Type `jenkins-bench() { script -qfec "$BIN/jenkins-bench $*" /dev/null | while IFS= read -r l; do printf '%s\n' "$l"; sleep 0.02; done; } && clear`
Enter
Wait
Show

Sleep 500ms
Type "jenkins-bench scan --demo"
Sleep 600ms
Enter
Sleep 12s
