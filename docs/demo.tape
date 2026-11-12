# Regenerate the demo GIF:  vhs docs/demo.tape   (needs https://github.com/charmbracelet/vhs)
# Records Tattle running the repository's own guilty *fixture* against localhost, not a real tool.
# Run `npm run build` first. The fixture needs ports and a fake HOME, so we drive it through the
# sample-card script, which sets all of that up.
Output docs/assets/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 700
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 45ms

Hide
Type "export NO_COLOR=1 PS1='$ ' && clear"
Enter
Show

Type "# a harmless command"
Enter
Type "npx @iamsaqibs/tattle run -- node -e \"console.log('hello')\""
Enter
Sleep 4s

Type "clear"
Enter
Type "# the guilty test fixture (fake secrets, localhost only)"
Enter
Type "node scripts/gen-sample-card.mjs"
Enter
Sleep 6s

Type "# a receipt anyone can verify"
Enter
Type "npx @iamsaqibs/tattle list"
Enter
Sleep 2s
