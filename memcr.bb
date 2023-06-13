SUMMARY = "memory checkpoint and restore"
HOMEPAGE = "https://github.com/LibertyGlobal/memcr"
SECTION = "console/tools"
DEPENDS = "util-linux-native openssl lz4"
RDEPENDS_${PN} = "libcrypto lz4"

INSANE_SKIP:${PN} += "ldflags"

LICENSE = "GPLv2"
LIC_FILES_CHKSUM = "file://COPYING;md5=0ba16794955006770904e8293abcbee5"

SRC_URI = "git://github.com/LibertyGlobal/memcr.git;protocol=https;branch=main"
SRCREV = "${AUTOREV}"

PV = "git${SRCPV}"

S = "${WORKDIR}/git"

do_compile () {
	oe_runmake COMPRESS_LZ4=1 CHECKSUM_MD5=1
}

do_install () {
	install -D -m 755 ${B}/memcr ${D}${bindir}/memcr
	install -D -m 755 ${B}/memcr-client ${D}${bindir}/memcr-client
}

FILES_${PN} = "${bindir}/memcr"
FILES_${PN} += " ${bindir}/memcr-client"
