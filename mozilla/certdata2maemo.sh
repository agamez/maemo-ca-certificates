#!/bin/sh
./certdata2pem.py

DIRS="common-ca blacklist"
for directory in $DIRS; do
	rm -f "$directory.txt"
	touch "$directory.txt"

	for cert in ${directory}/*.crt; do
		if [ "${cert}" = "${directory}"'/*.crt' ]; then continue; fi
		IDENTIFIER=$(openssl x509 -in "${cert}" -text -noout | 
			  grep 'X509v3 Subject Key Identifier:' -A 1 |
			  tail -1 |
			  tr -d ': ' | 
			  tr '[:upper:]' '[:lower:]')
		if [ "$IDENTIFIER" = "" ]; then
			echo "$cert doesn't possess a X509v3 Subject Key Identifier:" >&2
			continue
		fi

		if [ -e ${directory}/${IDENTIFIER}.pem ]; then
			LAST=$(ls -1v ${directory}/${IDENTIFIER}-*.pem 2>/dev/null| tail -1)
			LAST_N=$(echo $LAST | sed -r 's#.*-([0-9]+)\.pem#\1#g')
			NEXT=$(($LAST_N+1))
			NEWNAME="${directory}/${IDENTIFIER}-$NEXT.pem"
		else
			NEWNAME="${directory}/${IDENTIFIER}.pem"
		fi

		mv "$cert" "${NEWNAME}"
		echo "${NEWNAME}" >> "$directory.txt"
	done
done
