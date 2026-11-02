// FIDO2 / CTAP2 プロトコル実装 (Android 非依存の純 Kotlin/JVM モジュール)。
// Android SDK なしでビルド・単体テストできる。
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlin.jvm)
}

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_21)
    }
}

dependencies {
    testImplementation(libs.junit)
}
