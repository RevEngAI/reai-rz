# CmdGen Module

## Introduction

Rizin uses its own in-house built language `RzShell` to interpret it's interactive command line
inputs. To register commands for a plugin, one needs to describe each command, and provide it's handlers.
This is done through multiple structures like `RzCmdDesc`, `RzCmdDescArg` etc...

Instead of describing these commands manually, I've extracted out their code to parse Yaml descriptions
and generate C glue code. This glue code links the command descriptions with their command handlers.
This allows one to change command names anytime in future as long as the corresponding handlers remain
defined or are added.

## Adding New Commands

To add new commands, you just need to edit the `Reai.yaml.in` file inside `CmdGen/Yaml`. There are many
examples of these command descriptions in the `rizin/librz/core/cmd_descs` folder in rizin repository.
One can take reference from there and add new descriptions.

Each of these command descriptions will take name of command handler. These handlers must be defined
somewhere in the code that at the end of execution will get linked with the `reai_cmdgen` library.
In this plugin (at the time of writing), all handlers are defined in `Source/Rizin/CmdHandlers.c` file.

The signature of command handler may change depending on the types of argument it takes. Again, there
are lots of examples present in the rizin repo itself.
