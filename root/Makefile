VERSION = 1.18
TARGET  = dist

.PHONY: all clean

all: $(addprefix $(TARGET)/,$(wildcard img/*)) $(addprefix $(TARGET)/,$(wildcard css/*)) $(TARGET)/js/all.js $(TARGET)/js/pwn.js $(TARGET)/index.html $(TARGET)/payload $(TARGET)/manifest.appcache $(TARGET)/favicon.ico $(TARGET)/bootstrap/Meridian.tar.xz $(TARGET)/bootstrap/DH.tar.xz

$(TARGET)/img/%: img/% | $(TARGET)/img
	cp $^ $@

$(TARGET)/css/%: css/% | $(TARGET)/css
	closure-css $^ -o $@

$(TARGET)/js/all.js: js/utils.js js/version.js js/slider.js js/int64.js js/spyware.js | $(TARGET)/js # NOTE: order is important!
	closure-js -O SIMPLE --language_in ECMASCRIPT_2016 --language_out ECMASCRIPT5 $^ --js_output_file $@

$(TARGET)/js/pwn.js: js/pwn.js | $(TARGET)/js # minify only
	closure-js -O WHITESPACE_ONLY $^ --js_output_file $@

$(TARGET)/index.html: index.html | $(TARGET)
	perl -pe 'BEGIN{undef $$/;} s:<!--mergestart-->.*?<!--mergeend-->:<script src="js/all.js"></script>:sg;' $^ >$@

$(TARGET)/payload: ../glue/payload | $(TARGET)
	cp $^ $@

../glue/payload:
	JIT=1 $(MAKE) -C ../glue all

$(TARGET)/bootstrap/DH.tar.xz: ../glue/dep/doubleH3lix/DH.tar.xz | $(TARGET)/bootstrap
	cp $^ $@

$(TARGET)/bootstrap/Meridian.tar.xz: ../glue/dep/Meridian/Meridian.tar.xz | $(TARGET)/bootstrap
	cp $^ $@

$(TARGET)/manifest.appcache: manifest.appcache | $(TARGET)
	sed -E 's/__VERSION__/$(VERSION)/g' $^ >$@

$(TARGET)/favicon.ico: favicon.ico | $(TARGET)
	cp $^ $@

../glue/dep/doubleH3lix/DH.tar.xz:
	$(MAKE) -C ../glue/dep/doubleH3lix bootstrap

../glue/dep/Meridian/Meridian.tar.xz:
	$(MAKE) -C ../glue/dep/Meridian bootstrap

$(TARGET)/img: | $(TARGET)
	mkdir -p $@

$(TARGET)/css: | $(TARGET)
	mkdir -p $@

$(TARGET)/js: | $(TARGET)
	mkdir -p $@

$(TARGET)/bootstrap: | $(TARGET)
	mkdir -p $@

$(TARGET):
	mkdir -p $@

clean:
	rm -rf $(TARGET)

distclean: clean
	$(MAKE) -C ../glue distclean
