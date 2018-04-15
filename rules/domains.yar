rule domain {
    meta:
        author = "Adam LeTang (Moros)"
    strings:
        $domain_regex = /.*((.com)|(.org)|(.net)|(.edu))/ wide ascii
    condition:
        $domain_regex
}
