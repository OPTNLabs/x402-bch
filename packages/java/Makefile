JAVA ?= java
JAVAC ?= javac
BUILD_DIR ?= build/classes

.PHONY: test clean

test:
	$(RM) -r $(BUILD_DIR)
	mkdir -p $(BUILD_DIR)
	$(JAVAC) -d $(BUILD_DIR) src/main/java/X402Bch.java src/test/java/ConformanceTest.java
	cd $(CURDIR) && $(JAVA) -cp $(CURDIR)/$(BUILD_DIR) x402bch.ConformanceTest

clean:
	$(RM) -r build
