// App module. UNVERIFIED (see android/README.md) — no Android toolchain was
// available where this repo was started, so this has never been through Gradle.

plugins {
    id("com.android.application")
    kotlin("android")
}

android {
    namespace = "sh.vault.sealed"
    compileSdk = 35

    defaultConfig {
        applicationId = "sh.vault.sealed"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
        buildConfigField(
            "String",
            "API_BASE",
            "\"${(project.findProperty("apiBase") as String?) ?: "https://vault.example.com"}\"",
        )
    }

    buildFeatures { buildConfig = true }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
}

dependencies {
    // libsodium via JNI — the same primitive library as the web client.
    implementation("com.goterl:lazysodium-android:5.1.0@aar")
    implementation("net.java.dev.jna:jna:5.13.0@aar")

    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.media3:media3-exoplayer:1.4.1")
    implementation("androidx.media3:media3-ui:1.4.1")
    implementation("androidx.media3:media3-datasource:1.4.1")

    testImplementation("junit:junit:4.13.2")
    // Conformance: port web/src/conformance.test.ts here and read spec/crypto-vectors.json.
}
