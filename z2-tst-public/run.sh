#!/bin/bash

cd $(dirname $0)
#make

run() {
	tst_exec=$1
	ok=1

	echo === Test $tst_exec ===
	rm -f tst
	if ! ./$tst_exec ; then
		echo "Exec failed"
		ok=0
	fi

	[ "$ok" == "1" ] && echo OK
}

run_fail() {
	echo "=== fail ctx ==="
	failing_files=("bpf_check_ctx.o" "bpf_custom_check_ctx.o")
	ok=1
	for f in ${failing_files[@]}; do
		rm -f tst
		echo Testing file $f
		if ! ./fail_ctx $f ; then
			echo "Exec failed"
			ok=0
		fi
	done
	[ "$ok" == "1" ] && echo OK
}

do_check_perm() {
	echo "==== CHECK PERM"
	./check_perm /tmp/test && echo OK
}

run simple_write
run complex_write
run decide_no_calculate
run test_reset
run test_fork
run simple_write
run test_syscalls

echo "==== FAIL CTX"
run_fail

rm -f /tmp/test
touch /tmp/test
chown 0:0 /tmp/test
chmod 660 /tmp/test

do_check_perm "Same owner, 0660 mode"

chown 1000:0 /tmp/test
do_check_perm "Other user"

chown 0:1000 /tmp/test
do_check_perm "Other group"

chown 0:0 /tmp/test
chmod 664 /tmp/test
do_check_perm "Same owner, 0664 mode"
