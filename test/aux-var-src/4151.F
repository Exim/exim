# Exim filter

logfile DIR/test-stderr

logwrite "----- System filter -----"
logwrite "  acl_c0=\"$acl_c0\"\n  acl_c1=\"$acl_c1\"\n  acl_c2=\"$acl_c2\"\n  \
            acl_c3=\"$acl_c3\"\n  acl_c4=\"$acl_c4\"\n  acl_c5=\"$acl_c5\"\n  \
            acl_c6=\"$acl_c6\"\n  acl_c7=\"$acl_c7\"\n  acl_c8=\"$acl_c8\"\n  \
            acl_c9=\"$acl_c9\"\n  acl_m0=\"$acl_m0\"\n  acl_m1=\"$acl_m1\"\n  \
            acl_m2=\"$acl_m2\"\n  acl_m3=\"$acl_m3\"\n  acl_m4=\"$acl_m4\"\n  \
            acl_m5=\"$acl_m5\"\n  acl_m6=\"$acl_m6\"\n  acl_m7=\"$acl_m7\"\n  \
            acl_m8=\"$acl_m8\"\n  acl_m9=\"$acl_m9\"\n  \
            acl_m_foo=\"$acl_m_foo\"\n  acl_m_bar=\"$acl_m_bar\"\n  \
            acl_c_foo=\"$acl_c_foo\"\n  acl_c_bar=\"$acl_c_bar\"\n"  
logwrite "-------------------------"

# End
