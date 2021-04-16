#!/bin/bash

ls arc | xargs -I{} sh -c 'echo "git mv ./arc/" | tr -d "\n" ; echo "{} ./arc/" | tr -d "\n" ; grep "^{}" ./arc_fn'
ls arm | xargs -I{} sh -c 'echo "git mv ./arm/" | tr -d "\n" ; echo "{} ./arm/" | tr -d "\n" ; grep "^{}" ./arm_fn'
ls mips | xargs -I{} sh -c 'echo "git mv ./mips/" | tr -d "\n" ; echo "{} ./mips/" | tr -d "\n" ; grep "^{}" ./mips_fn'
ls mipsel | xargs -I{} sh -c 'echo "git mv ./mipsel/" | tr -d "\n" ; echo "{} ./mipsel/" | tr -d "\n" ; grep "^{}" ./mipsel_fn'
ls mips64 | xargs -I{} sh -c 'echo "git mv ./mips64/" | tr -d "\n" ; echo "{} ./mips64/" | tr -d "\n" ; grep "^{}" ./mips64_fn'
ls motorola | xargs -I{} sh -c 'echo "git mv ./motorola/" | tr -d "\n" ; echo "{} ./motorola/" | tr -d "\n" ; grep "^{}" ./motorola_fn'
ls powerpc | xargs -I{} sh -c 'echo "git mv ./powerpc/" | tr -d "\n" ; echo "{} ./powerpc/" | tr -d "\n" ; grep "^{}" ./powerpc_fn'
ls renesas | xargs -I{} sh -c 'echo "git mv ./renesas/" | tr -d "\n" ; echo "{} ./renesas/" | tr -d "\n" ; grep "^{}" ./renesas_fn'
ls sparc | xargs -I{} sh -c 'echo "git mv ./sparc/" | tr -d "\n" ; echo "{} ./sparc/" | tr -d "\n" ; grep "^{}" ./sparc_fn'
ls x86 | xargs -I{} sh -c 'echo "git mv ./x86/" | tr -d "\n" ; echo "{} ./x86/" | tr -d "\n" ; grep "^{}" ./x86_fn'
ls x86_64 | xargs -I{} sh -c 'echo "git mv ./x86_64/" | tr -d "\n" ; echo "{} ./x86_64/" | tr -d "\n" ; grep "^{}" ./x86_64_fn'
