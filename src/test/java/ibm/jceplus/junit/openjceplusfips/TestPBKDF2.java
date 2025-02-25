/*
 * Copyright IBM Corp. 2023, 2025
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution.
 */

package ibm.jceplus.junit.openjceplusfips;

import ibm.jceplus.junit.base.BaseTestPBKDF2;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.TestInstance.Lifecycle;

@TestInstance(Lifecycle.PER_CLASS)
public class TestPBKDF2 extends BaseTestPBKDF2 {

    @BeforeAll
    public void beforeAll() {
        Utils.loadProviderTestSuite();
        setProviderName(Utils.TEST_SUITE_PROVIDER_NAME);
    }

    @Override
    @Disabled("The KAT published salt value is not acceptable for FIPS, disable this test.")  
    public void testPBKDF2KAT() throws Exception {
    }
}
