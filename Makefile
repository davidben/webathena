all: app/scripts/webathena.js app/scripts/webathena-ui.js

compiler.jar: download-compiler.sh
	./download-compiler.sh

CORE_JS_SOURCES := \
	crc32.js \
	typedarray.js \
	util.js \
	arrayutils.js \
	asn1.js \
	krb_proto.js \
	kcrypto.js \
	krb.js

UI_JS_SOURCES := \
	winchan.js \
	kdc.js \
	request_ticket.js \
	ui.js

# For now, only build with simple optimizations. We can't run with
# advanced ones yet.
app/scripts/webathena.js: compiler.jar $(addprefix app/scripts/,$(CORE_JS_SOURCES))
	cd app/scripts && java -jar ../../compiler.jar \
		$(addprefix --js ,$(CORE_JS_SOURCES)) \
		--js_output_file webathena.js.tmp \
		--language_in ECMASCRIPT5_STRICT \
		--source_map_format=V3 \
		--create_source_map webathena.js.map
	echo '//@ sourceMappingURL=webathena.js.map' >> app/scripts/webathena.js.tmp
	mv app/scripts/webathena.js.tmp $@

app/scripts/webathena-ui.js: compiler.jar $(addprefix app/scripts/,$(UI_JS_SOURCES))
	cd app/scripts && java -jar ../../compiler.jar \
		$(addprefix --js ,$(UI_JS_SOURCES)) \
		--js_output_file webathena-ui.js.tmp \
		--language_in ECMASCRIPT5_STRICT \
		--source_map_format=V3 \
		--create_source_map webathena-ui.js.map
	echo '//@ sourceMappingURL=webathena-ui.js.map' >> app/scripts/webathena-ui.js.tmp
	mv app/scripts/webathena-ui.js.tmp $@
