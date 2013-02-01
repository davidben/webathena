all: web_scripts/js/webathena.js web_scripts/js/webathena-ui.js

compiler.jar: download-compiler.sh
	./download-compiler.sh

CORE_JS_SOURCES := \
	crc32.js \
	typedarray.js \
	util.js \
	arrayutils.js \
	asn1.js \
	krb.js \
	kcrypto.js \
	kdc.js

UI_JS_SOURCES := \
	winchan.js \
	request_ticket.js \
	ui.js

# For now, only build with simple optimizations. We can't run with
# advanced ones yet.
web_scripts/js/webathena.js: compiler.jar $(addprefix web_scripts/js/,$(CORE_JS_SOURCES))
	cd web_scripts/js && java -jar ../../compiler.jar \
		$(addprefix --js ,$(CORE_JS_SOURCES)) \
		--js_output_file webathena.js.tmp \
		--language_in ECMASCRIPT5_STRICT \
		--source_map_format=V3 \
		--create_source_map webathena.js.map
	echo '//@ sourceMappingURL=webathena.js.map' >> web_scripts/js/webathena.js.tmp
	mv web_scripts/js/webathena.js.tmp $@

web_scripts/js/webathena-ui.js: compiler.jar $(addprefix web_scripts/js/,$(UI_JS_SOURCES))
	cd web_scripts/js && java -jar ../../compiler.jar \
		$(addprefix --js ,$(UI_JS_SOURCES)) \
		--js_output_file webathena-ui.js.tmp \
		--language_in ECMASCRIPT5_STRICT \
		--source_map_format=V3 \
		--create_source_map webathena-ui.js.map
	echo '//@ sourceMappingURL=webathena-ui.js.map' >> web_scripts/js/webathena-ui.js.tmp
	mv web_scripts/js/webathena-ui.js.tmp $@
