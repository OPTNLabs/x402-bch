JAVA ?= java
JAVAC ?= javac
BUILD_DIR ?= build/classes
JAVA_SOURCES := $(shell find src/main/java -name '*.java' -print)

.PHONY: test jar clean

test:
	$(RM) -r $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)
	$(JAVAC) -d $(BUILD_DIR) $(JAVA_SOURCES) src/test/java/ConformanceTest.java src/test/java/ModularApiTest.java src/test/java/SdkAdapterTest.java
	cd $(CURDIR) && $(JAVA) -cp $(CURDIR)/$(BUILD_DIR) x402bch.ConformanceTest
	cd $(CURDIR) && $(JAVA) -cp $(CURDIR)/$(BUILD_DIR) x402bch.ModularApiTest
	cd $(CURDIR) && $(JAVA) -cp $(CURDIR)/$(BUILD_DIR) x402bch.SdkAdapterTest

jar:
	$(RM) -r build/classes build/x402-bch.jar
	mkdir -p build/classes
	$(JAVAC) -d build/classes $(JAVA_SOURCES)
	cp src/main/resources/bip39-english.txt build/classes/
	jar --create --file build/x402-bch.jar -C build/classes .

clean:
	$(RM) -r build
