Lua Configurator Documentation

## WHAT IS IT?
A tool that automatically creates a graphical interface for editing variables in .lua/.hks files.

## HOW TO USE IT?
1. Create your .lua or .hks file.
2. Add the structure:

```lua
--// READ VARIABLES

-- your variables here

--// END READ VARIABLES
```

3. Run Lua Configurator.
4. Your file will appear as an interactive block.

## WHERE TO SAVE?
Look for files in the mod/action/script path and subfolders within script.

## TYPES OF VARIABLES

### Numeric:
```lua
-- [UI] NAME: Deflection Time
-- [UI] HINT: Time window to deflect
local v_Numeric = 0.3
```

### Boolean:
```lua
-- [UI] NAME: Automatic Assistant
-- [UI] HINT: Helps with combo deflection
local v_Boolean = true
```

### String:
```lua
-- [UI] NAME: Auto-Choice
-- [UI] HINT: Reply automatic
local v_String = “Hello!”
```

### Selector:
```lua
-- [UI] NAME: Difficulty
-- [UI] HINT: Difficulty level
-- [UI] SELECTOR: EASY, NORMAL, HARD
local v_Selector = “NORMAL”
```

### Tables:
```lua
-- [UI] NAME: Damage Settings
local v_Table = {
    -- [UI] TABLEFIELD_NAME: Physical Damage
    Physical = 1.0,
    -- [UI] TABLEFIELD_NAME: Magic Damage
    Magico = 0.8,
    -- [UI] TABLEFIELD_NAME: Critical Damage
    Critico = 2.0,
}
```

### Tags:
```lua
-- [UI] NAME: Example Tag
-- [UI] HINT: Counter attack after deflecting
-- [UI] TAG: UNSUPPORTED
-- [UI] TAG_COLOR: RED
local v_GuardCounterType = 0
```

## TAG COLORS
```lua
RED
GREEN
BLUE
YELLOW
ORANGE
PURPLE
CYAN
PINK
```

### Tags with automatic colors:
```moon
UNSUPPORTED -> RED
EXPERIMENTAL -> ORANGE
NEW -> GREEN
DEPRECATED -> YELLOW
BETA -> PURPLE
ALPHA -> CYAN
WIP -> ORANGE
STABLE -> GREEN
LEGACY -> GRAY
```

## METADATA
```lua
NAME: Display name
HINT: Help text
SELECTOR: Dropdown options
TAG: Colored label
TAG_COLOR: Tag color
TAG_COLOR_[NAME]: Specific color for each tag
TABLEFIELD_NAME: Table field name
TABLEFIELD_HINT: Table field hint
TABLEFIELD_SELECTOR: Table field selector
```

## EXAMPLES

```lua
--// READ VARIABLES

-- [UI] NAME: Active Mode
-- [UI] HINT: Enables/disables the mod
-- [UI] TAG: STABLE
local v_Boolean = true

-- [UI] NAME: Deflection Time
-- [UI] HINT: Window in seconds
local v_Number = 0.3

-- [UI] NAME: Game Type
-- [UI] HINT: Gameplay style
-- [UI] SELECTOR: VANILLA, SEKIRO, CUSTOM
-- [UI] TAG: NEW
-- [UI] TAG_COLOR: GREEN
local v_Selector = “SEKIRO”

-- [UI] NAME: Counter Style
-- [UI] HINT: Counter attack after deflecting
-- [UI] SELECTOR: 1 = SEKIRO, 0 = STANDARD
-- [UI] TAG: UNSUPPORTED
-- [UI] TAG_COLOR: RED
local v_GuardCounterType = 0

-- [UI] NAME: Advanced Settings
-- [UI] HINT: Experimental features
-- [UI] TAG: EXPERIMENTAL
-- [UI] TAG: WIP
-- [UI] TAG_COLOR_EXPERIMENTAL: ORANGE
-- [UI] TAG_COLOR_WIP: YELLOW
local v_AdvancedSettings = false

-- [UI] NAME: Damage Settings
local v_Table = {
    -- [UI] TABLEFIELD_NAME: Physical Damage
    Physical = 1.0,
    -- [UI] TABLEFIELD_NAME: Magic Damage
    Magic = 0.8,
    -- [UI] TABLEFIELD_NAME: Critical Damage
    Critical = 2.0,
}

--// END READ VARIABLES
```

## TIPS AND BEST PRACTICES

### For Tags:
- Use tags for important statuses: UNSUPPORTED, EXPERIMENTAL, DEPRECATED
- Consistent colors: red for issues, green for ready features
- Tag limit: maximum 3-4 per variable
- Descriptive tags: WIP, STABLE, etc.

### For Variables:
- Clear names: v_DeflectWindow instead of v_DW
- Sensible default values
- Helpful hints: explain what the variable does and possible values
- Organized sections: use titles or separators to group related variables

### IMPORTANT NOTES
- Always use --// READ VARIABLES and --// END READ VARIABLES
- Tags are optional but recommended for important statuses
- Default values should make sense
- Colors can be names (RED) or HEX (#FF0000)
- Tag system works for normal variables and tables

### RECENT UPDATES
- Tag System: support for colored tags
- Automatic Colors: predefined colors for common tags
- Multiple Tags: multiple tags per variable
- Specific Colors: set different colors for each tag
- Persistence: tags saved in the Lua file

## TROUBLESHOOTING

Tags do not appear:
- Check syntax: -- [UI] TAG: TAG_NAME
- Make sure there is a space after [UI]
- Tags are case sensitive

Colors do not work:
- Use English color names: RED, GREEN, BLUE, etc.
- Or HEX codes: #FF0000
- Check if the color exists in the mapping

Lua Configurator – Turn your Lua code into a powerful graphical interface!
