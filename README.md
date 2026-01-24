# nu_plugin_ebpf

This is a [Nushell](https://nushell.sh/) plugin called "ebpf".

## Installing

```nushell
> cargo install --path .
```

## Usage

FIXME: This reflects the demo functionality generated with the template. Update this documentation
once you have implemented the actual plugin functionality.

```nushell
> plugin add ~/.cargo/bin/nu_plugin_ebpf
> plugin use ebpf
> ebpf attach Ellie
Hello, Ellie. How are you today?
> ebpf attach --shout Ellie
HELLO, ELLIE. HOW ARE YOU TODAY?
```
