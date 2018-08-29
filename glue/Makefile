TARGET   = payload
SRC      = src
INC      = include
LIB      = lib
OBJ      = obj
DEP      = dep
ifdef JIT
GEN      = $(DEP)/jit/genesis.S
else
GEN      =
endif
DEP_C    = $(patsubst $(SRC)/%.m,%,$(wildcard $(SRC)/*.m))
DEP_CXX  = $(patsubst $(SRC)/%.mm,%,$(wildcard $(SRC)/*.mm))
IGXX     = xcrun -sdk iphoneos clang++ -arch arm64
FLAGS   ?= -Wall -O3 -fobjc-arc -miphoneos-version-min=10.0 $(CFLAGS)
LFLAGS  ?= -Wl,-x -Wl,-dead_strip -L$(wildcard $(DEP)/curl-*)/lib/.libs -lcurl -L$(DEP)/Meridian -lMeridian -L$(LIB) -ldoubleH3lix -loffsetfinder64 -limg4tool -lplist++ -lplist -lz -larchive -F. -framework IOKit -framework Security $(LDFLAGS)
ifdef JIT
LFLAGS  += -Wl,-exported_symbols_list,keep.txt
endif
FILES   := $(addsuffix .o, $(addprefix $(OBJ)/c/, $(DEP_C))) $(addsuffix .o, $(addprefix $(OBJ)/c++/, $(DEP_CXX)))

.PHONY: all clean distclean

all: $(TARGET)

$(TARGET): $(DEP)/curl-*/lib/.libs/libcurl.a $(DEP)/Meridian/libMeridian.a $(FILES)
	$(IGXX) -o $@ $(FLAGS) $(GEN) $(FILES) $(LFLAGS)

$(OBJ)/c/%.o: $(SRC)/%.m | $(OBJ)/c
	$(IGXX) -c -o $@ $(FLAGS) -xobjective-c -std=gnu11 $< -I$(INC)

$(OBJ)/c++/%.o: $(SRC)/%.mm | $(OBJ)/c++
	$(IGXX) -c -o $@ $(FLAGS) -xobjective-c++ -std=gnu++14 $< -I$(INC)

$(OBJ)/c:
	mkdir -p $@

$(OBJ)/c++:
	mkdir -p $@

$(DEP)/Meridian/libMeridian.a:
	$(MAKE) -C $(DEP)/Meridian all

$(DEP)/curl-*/lib/.libs/libcurl.a:
	cd $(DEP)/curl-* && ./configure --enable-static --disable-shared --host=aarch64-apple-darwin --without-ssl --with-darwinssl CC='xcrun -sdk iphoneos clang -arch arm64' CFLAGS='-miphoneos-version-min=10.0'
	$(MAKE) -C $(DEP)/curl-* all

clean:
	rm -rf $(TARGET) $(OBJ)

distclean: clean
	$(MAKE) -C $(DEP)/Meridian clean
ifneq (,$(wildcard $(DEP)/curl-*/Makefile))
	$(MAKE) -C $(DEP)/curl-* distclean
endif
