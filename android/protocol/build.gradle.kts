plugins {
    kotlin("jvm")
}

dependencies {
    testImplementation(kotlin("test"))
}

kotlin {
    jvmToolchain(21)
}

sourceSets {
    // The vector fixtures live at <repo>/protocol/test-vectors, outside this
    // module, so the runner is told where to look rather than duplicating them.
    test {
        resources.srcDir("../../../protocol/test-vectors")
    }
}

tasks.test {
    useJUnitPlatform()
    testLogging {
        events("passed", "failed", "skipped")
        showStandardStreams = true
    }
}