#!/usr/bin/env python3
import sys
from pathlib import Path
sys.dont_write_bytecode=True; sys.path.insert(0,str(Path(__file__).parents[1]))
from validate import jcs, load_json
sys.stdout.buffer.write(jcs(load_json(Path(sys.argv[1]))))
