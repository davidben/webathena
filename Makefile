all: web_scripts/js/webathena.js

compiler.jar: download-compiler.sh
	./download-compiler.sh

JS_SOURCES := \
	winchan.js \
	util.js \
	crc32.js \
	asn1.js \
	krb.js \
	kcrypto.js \
	kdc.js \
	request_ticket.js \
	ui.js

# For now, only build with simple optimizations. We can't run with
# advanced ones yet.
web_scripts/js/webathena.js: compiler.jar $(addprefix web_scripts/js/,$(JS_SOURCES))
	cd web_scripts/js && java -jar ../../compiler.jar \
		$(addprefix --js ,$(JS_SOURCES)) \
		--js_output_file webathena.js.tmp \
		--language_in ECMASCRIPT5_STRICT \
		--source_map_format=V3 \
		--create_source_map webathena.js.map
	echo '//@ sourceMappingURL=webathena.js.map' >> web_scripts/js/webathena.js.tmp
	mv web_scripts/js/webathena.js.tmp $@
