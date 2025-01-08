----


 `<comando> 2` -> 2 hace referencia a `stderr` *standard errors* 
- `<comando> 2>/dev/null` -> Mandando todos los errores al [[Basurero]]

 `<comando> >` -> > hace referencia a `stdout` *standard out* 
- `<comando> >/dev/null` -> Mandando todos los outs al [[Basurero]]

- `<comando> > /dev/null 2>&1`  -> Mandando el output al Basurero pero tambien con `2>&1` convertis los `stderr` a `stdout`

- `<comando> &> /dev/null`  -> Mandar al Basurero tanto `stderr` como `stdout`




-----