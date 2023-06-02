# Copyright (c) 2023 Cesanta Software Limited
# All rights reserved

CWD     = $(realpath $(CURDIR))

# Needs network setup, see mongoose/examples/mip-pcap/README.md
e1: mongoose
	echo '#pragma once' > /tmp/mongoose_custom.h
	echo '#define MG_ENABLE_FILE 0' >> /tmp/mongoose_custom.h
	echo '#define MG_ENABLE_POLL 1' >> /tmp/mongoose_custom.h
	echo '#define MG_ENABLE_LINES 1' >> /tmp/mongoose_custom.h
	echo '#include <stdbool.h>' >> /tmp/mongoose_custom.h
	echo '#include <stdlib.h>' >> /tmp/mongoose_custom.h
	echo '#include <stdint.h>' >> /tmp/mongoose_custom.h
	echo '#include <stdarg.h>' >> /tmp/mongoose_custom.h
	echo '#include <string.h>' >> /tmp/mongoose_custom.h
	echo '#include <errno.h>' >> /tmp/mongoose_custom.h
	echo '#include <time.h>' >> /tmp/mongoose_custom.h
	echo '#include <fcntl.h>' >> /tmp/mongoose_custom.h
	echo '#include <unistd.h>' >> /tmp/mongoose_custom.h
	echo '#include <stdio.h>' >> /tmp/mongoose_custom.h
	echo '#include <signal.h>' >> /tmp/mongoose_custom.h
	echo '#include "mip.h"' >> /tmp/mongoose_custom.h
	grep mip_ mongoose/examples/mip-pcap/main.c || (perl -pi -e 's/mg_tcpip/mip/g' mongoose/examples/mip-pcap/main.c ; perl -pi -e 's/mip_init.*/mip_init(&mif);/g' mongoose/examples/mip-pcap/main.c ;)
	make -C mongoose/examples/mip-pcap/ clean all ARGS="-i feth0" CFLAGS_MONGOOSE="-I$(CWD) -I/tmp $(CWD)/mip.c -DMG_ARCH=MG_ARCH_CUSTOM -D_SYS_SOCKET_H=1 -D_NETDB_H=1 -Dlib_pcap_socket_h=1 -DSOCKET=int -Dmip_random=mg_random -Dmip_millis=mg_millis"

e2: mongoose
	echo '#pragma once' > /tmp/mongoose_custom.h
	echo '#define MG_ARCH MG_ARCH_NEWLIB' >> /tmp/mongoose_custom.h
	echo '#define MG_ENABLE_FILE 0' >> /tmp/mongoose_custom.h
	echo '#define MG_ENABLE_POLL 1' >> /tmp/mongoose_custom.h
	echo '#include "mip.h"' >> /tmp/mongoose_custom.h
	make -C mongoose/examples/stm32/nucleo-f746zg-baremetal all CFLAGS_EXTRA="-I$(CWD) -I/tmp $(CWD)/mip.c -Dmip_random=mg_random -Dmip_millis=mg_millis"

mongoose:
	ln -fs ../mongoose $@
#	git clone --depth 1 -b master https://github.com/cesanta/mongoose $@

clean:
	rm -rf *.o *.gc* *.dSYM *.exe *.obj *.pdb mongoose
