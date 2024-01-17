
plugins {
    kotlin("jvm") version "1.9.0"
    kotlin("plugin.serialization") version "1.9.0"
    `jvm-test-suite`

    application
}

repositories {
    mavenCentral()
    maven {
        setUrl("https://plugins.gradle.org/m2/")
    }
    maven {
        setUrl("https://maven.scijava.org/content/repositories/public/")
    }
}

dependencies {

    implementation("org.xerial:sqlite-jdbc:3.43.0.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.5.1")
    implementation("javax.activation:activation:1.1.1")

    // For parsing the server's config file
    implementation("io.hotmoka:toml4j:0.7.3")

    // JDBC Driver for Postgres because the integration tests interact directly with
    // the database.
    implementation("org.postgresql:postgresql:42.6.0")

    val coroutinesVersion = "1.7.2"
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:$coroutinesVersion")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-jdk8:$coroutinesVersion")

    // Needed by keznacl
    implementation("com.github.alphazero:Blake2b:bbf094983c")
    implementation("org.purejava:tweetnacl-java:1.1.2")
    implementation("de.mkammerer:argon2-jvm:2.11")

    // JUnit 5 with Kotlin
    testImplementation("org.jetbrains.kotlin:kotlin-test-junit5")
    testImplementation("org.junit.jupiter:junit-jupiter-engine:5.9.2")

    // For the DNSHandler class
    implementation("org.minidns:minidns-hla:1.0.4")
}

testing {
    suites {
        val integrationTest by registering(JvmTestSuite::class) {
            dependencies {
                implementation(project())
                implementation("javax.activation:activation:1.1.1")

                // TOML parsing needed for loading the mensagod server config file
                implementation("com.moandjiezana.toml:toml4j:0.7.2")

                // JDBC Driver for Postgres because the integration tests interact directly with
                // the database.
                implementation("org.postgresql:postgresql:42.6.0")

                // For easy recursive deletion of directories
                implementation("commons-io:commons-io:2.13.0")

                val coroutinesVersion = "1.7.2"
                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:$coroutinesVersion")
                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-jdk8:$coroutinesVersion")

                // For DNS testing
                implementation("org.minidns:minidns-hla:1.0.4")
            }
        }
    }
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(17))
    }
}
application {
    // Define the main class for the application.
    mainClass.set("mensagod.AppKt")
}
