Output demo.gif

Set FontSize 13
Set Width 800
Set Height 516
Set Theme "Dracula"
Set PlaybackSpeed 1

# Launch TUI with cached data (no sync)
Type "./MailScrub --no-sync"
Enter
Sleep 4s

# Show sorting: count → sender A-Z → newest first
Type "o"
Sleep 2s
Type "o"
Sleep 2s

# Select two rows
Down
Sleep 400ms
Space
Sleep 400ms
Down
Sleep 400ms
Space
Sleep 800ms

# Unsubscribe
Type "u"
Sleep 1.5s

# Confirm unsubscribe
Type "y"
Sleep 3s

# Confirm delete emails too
Type "y"
Sleep 4s

# Show help screen
Type "?"
Sleep 3s

# Exit help, then quit
Type "q"
Sleep 500ms
Type "q"
Sleep 1s
