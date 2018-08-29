TARGET    = libMeridian.a
DMG       = Meridian.dmg
BOOTSTRAP = Meridian.tar.xz
SRC       = src
INC       = headers
OBJ       = obj
DEP_C     = $(patsubst $(SRC)/%.m,%,$(wildcard $(SRC)/*.m)) \
            $(patsubst $(SRC)/helpers/%.m,%,$(wildcard $(SRC)/helpers/*.m)) $(patsubst $(SRC)/helpers/%.c,%,$(wildcard $(SRC)/helpers/*.c)) \
            $(patsubst $(SRC)/mach/%.c,%,$(wildcard $(SRC)/mach/*.c)) \
            $(patsubst $(SRC)/patchfinders/%.m,%,$(wildcard $(SRC)/patchfinders/*.m)) $(patsubst $(SRC)/patchfinders/%.c,%,$(wildcard $(SRC)/patchfinders/*.c))
IGCC      = xcrun -sdk iphoneos clang++ -arch arm64
FLAGS    ?= -Wall -O3 -DHEADLESS=1 -fobjc-arc -miphoneos-version-min=10.0 $(CFLAGS)
IFLAGS   ?= -I$(INC) -I$(SRC) -I$(SRC)/helpers -I$(SRC)/mach -I$(SRC)/patchfinders

.PHONY: all bootstrap clean

all: $(TARGET)

$(TARGET): $(addsuffix .o, $(addprefix $(OBJ)/, $(DEP_C)))
	xcrun -sdk iphoneos libtool -static -o $@ $^

$(OBJ)/%.o: $(SRC)/%.m | $(OBJ)
	$(IGCC) -c -o $@ $(FLAGS) -xobjective-c -std=gnu11 $< $(IFLAGS)

$(OBJ)/%.o: $(SRC)/helpers/%.m | $(OBJ)
	$(IGCC) -c -o $@ $(FLAGS) -xobjective-c -std=gnu11 $< $(IFLAGS)

$(OBJ)/%.o: $(SRC)/helpers/%.c | $(OBJ)
	$(IGCC) -c -o $@ $(FLAGS) -xobjective-c -std=gnu11 $< $(IFLAGS)

$(OBJ)/%.o: $(SRC)/mach/%.c | $(OBJ)
	$(IGCC) -c -o $@ $(FLAGS) -xobjective-c -std=gnu11 $< $(IFLAGS)

$(OBJ)/%.o: $(SRC)/patchfinders/%.m | $(OBJ)
	$(IGCC) -c -o $@ $(FLAGS) -xobjective-c -std=gnu11 $< $(IFLAGS)

$(OBJ)/%.o: $(SRC)/patchfinders/%.c | $(OBJ)
	$(IGCC) -c -o $@ $(FLAGS) -xobjective-c -std=gnu11 $< $(IFLAGS)

$(OBJ):
	mkdir -p $@

bootstrap: $(BOOTSTRAP)

$(BOOTSTRAP): bootstrap/*
	cd bootstrap && bsdtar -cJf ../$@ ./*

clean:
	rm -rf $(TARGET) $(OBJ) $(BOOTSTRAP)
