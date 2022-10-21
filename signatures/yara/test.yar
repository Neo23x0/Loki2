rule test_rule {
    meta:
        score = 60
    strings:
        $x1 = "netcat" fullword ascii
        $x2 = "License" fullword ascii
    condition:
        1 of them
}
