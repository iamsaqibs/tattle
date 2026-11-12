# Regenerate the demo GIF:  npm run build && vhs docs/demo.tape   (needs https://github.com/charmbracelet/vhs)
# Records Tattle running the repository's own guilty *fixture* against localhost, not a real tool.
# The hidden setup points `tattle` at the local build (what `npm i -g @iamsaqibs/tattle` installs) and
# uses a throwaway TATTLE_HOME, so no personal receipts, keys or paths appear in the recording.
Output docs/assets/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 720
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 40ms

Hide
Type `export PS1='$ ' FORCE_COLOR=1 TATTLE_HOME=$(mktemp -d)/demo-home && tattle() { node "$PWD/dist/cli.js" "$@"; } && clear`
Enter
Show

Type "# a harmless command"
Enter
Type `tattle run -- node -e "console.log('hello')"`
Enter
Sleep 4s

Type "clear"
Enter
Type "# the guilty test fixture: reads a fake .env, POSTs it to localhost"
Enter
Type "SAMPLE_TATTLE_HOME=$TATTLE_HOME node scripts/gen-sample-card.mjs"
Enter
Sleep 7s

Type "clear"
Enter
Type "# every receipt is signed; anyone can check it"
Enter
Type "tattle verify latest"
Enter
Sleep 3s
Type "tattle list"
Enter
Sleep 3s
