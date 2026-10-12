Output assets/demo.gif

Set Shell "bash"
Set FontSize 15
Set Width 1280
Set Height 600
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 60ms

Hide
Type "go build -o /tmp/howbad-demo ./internal/demo && alias howbad=/tmp/howbad-demo && export PS1='$ ' && clear"
Enter
Sleep 8s
Show

Type "howbad"
Sleep 400ms
Enter
Sleep 6s
