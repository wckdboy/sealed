// UNVERIFIED — see android/README.md.
plugins {
    id("com.android.application") version "8.7.0" apply false
    kotlin("android") version "2.0.20" apply false
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}
