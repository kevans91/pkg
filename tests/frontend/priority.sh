#! /usr/bin/env atf-sh

. $(atf_get_srcdir)/test_environment.sh

tests_init \
        dependency_priorities \
        dependency_priorities_reversed

dependency_priorities_full() {
        priorityA=$1
		priorityB=$2
		if [ ${priorityA} -gt ${priorityB} ]; then
			expectedRepo="repoA"
		else
			expectedRepo="repoB"
		fi
		touch pkgA.file
        touch pkgB.file

        cat << EOF > pkgA.ucl
name: pkgA
origin: misc/pkgA
version: "1.0"
maintainer: test
categories: [test]
comment: a test
www: http://test
prefix: /usr/local
desc: <<EOD
Yet another test
EOD
deps:   {
          pkgB: {
                origin: "misc/pkgB",
                version: "1.0"
              }
        }
files: {
    ${TMPDIR}/pkgA.file: "",
}
EOF

        cat << EOF > pkgB.ucl
name: pkgB
origin: misc/pkgB
version: "1.0"
maintainer: test
categories: [test]
comment: a test
www: http://test
prefix: /usr/local
desc: <<EOD
Yet another test
EOD
files: {
    ${TMPDIR}/pkgB.file: "",
}
EOF

	mkdir reposconf
        cat << EOF > reposconf/repos.conf
repoA: {
        url: file://${TMPDIR}/repoA,
        enabled: true,
		priority: ${priorityA}
}
repoB: {
        url: file://${TMPDIR}/repoB,
        enabled: true,
		priority: ${priorityB}
}

EOF

        for p in pkgA pkgB; do
                atf_check \
                        -o ignore \
                        -e empty \
                        -s exit:0 \
                        pkg create -o ${TMPDIR}/repoA -M ./${p}.ucl
        done

        atf_check \
                -o inline:"Creating repository in ${TMPDIR}/repoA:  done\nPacking files for repository:  done\n" \
                -e empty \
                -s exit:0 \
                pkg repo -o ${TMPDIR}/repoA ${TMPDIR}/repoA


        for p in pkgA pkgB; do
                atf_check \
                        -o ignore \
                        -e empty \
                        -s exit:0 \
                        pkg create -o ${TMPDIR}/repoB -M ./${p}.ucl
        done

        atf_check \
                -o inline:"Creating repository in ${TMPDIR}/repoB:  done\nPacking files for repository:  done\n" \
                -e empty \
                -s exit:0 \
                pkg repo -o ${TMPDIR}/repoB ${TMPDIR}/repoB

OUTPUT_CASE1="Updating repoA repository catalogue...
${JAILED}Fetching meta.conf:  done
${JAILED}Fetching packagesite.txz:  done
Processing entries:  done
repoA repository update completed. 2 packages processed.
Updating repoB repository catalogue...
${JAILED}Fetching meta.conf:  done
${JAILED}Fetching packagesite.txz:  done
Processing entries:  done
repoB repository update completed. 2 packages processed.
All repositories are up to date.
Checking integrity... done (0 conflicting)
The following 2 package(s) will be affected (of 0 checked):

New packages to be INSTALLED:
	pkgA: 1.0 [${expectedRepo}]
	pkgB: 1.0 [${expectedRepo}]

Number of packages to be installed: 2
${JAILED}[1/2] Installing pkgB-1.0...
${JAILED}[1/2] Extracting pkgB-1.0:  done
${JAILED}[2/2] Installing pkgA-1.0...
${JAILED}[2/2] Extracting pkgA-1.0:  done
"

        atf_check \
                -o inline:"${OUTPUT_CASE1}" \
                -s exit:0 \
                pkg -o REPOS_DIR="${TMPDIR}/reposconf" -o PKG_CACHEDIR="${TMPDIR}" install -y pkgA
}

dependency_priorities_body() {
	dependency_priorities_full 10 5
}

dependency_priorities_reversed_body() {
	dependency_priorities_full 5 10
}
