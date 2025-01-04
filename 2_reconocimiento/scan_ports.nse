-- HEAD --

description = [[
    Script escanea puertos abiertos por TCP
]]

-- RULE --

portrule = function(host, port)
    -- retornamos true si el protocolo es tcp y el estado es open
    return port.protocol == "tcp" and port.state == "open"
end

-- ACTION --

action = function(host, port)
    -- mostramos el puerto abierto
    return string.format("Puerto %d abierto", port.number)
end
