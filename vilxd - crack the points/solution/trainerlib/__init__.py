"""
Portable helper package for Windows trainers.

Copy the `trainerlib/` directory between projects to reuse:
- `bits`: arithmetic/bit helpers
- `asm`: instruction encoders (jmp/call)
- `winapi`: WinAPI process + remote memory patch helpers
"""

from .bits import *  # noqa: F403
from .asm import *  # noqa: F403
from .winapi import *  # noqa: F403
