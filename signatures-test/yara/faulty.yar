rule faulty_rule {
    strings:
        $a1 = "valar"
        $a2 = "morghulis"
    condition:
        $a1
}