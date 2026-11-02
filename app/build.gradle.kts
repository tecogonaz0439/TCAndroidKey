plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "net.tecogonaz.tcandroidkey"
    compileSdk = 37

    defaultConfig {
        applicationId = "net.tecogonaz.tcandroidkey"
        // Android 15 以上 (要件)。
        minSdk = 35
        targetSdk = 37
        versionCode = 1
        versionName = "0.1.0"
    }

    signingConfigs {
        // 開発用の共通デバッグ署名鍵 (秘密ではない)。クラウド/ローカルどちらでビルドしても同じ署名になり、
        // 端末上のアプリを上書き更新できる (アンインストールすると Keystore の FIDO 鍵が全て消えるため)。
        getByName("debug") {
            storeFile = file("debug.keystore")
            storePassword = "android"
            keyAlias = "androiddebugkey"
            keyPassword = "android"
        }
        // リリース署名は環境変数で与える (keystore/ は Git 管理対象外)。
        create("release") {
            storeFile = rootProject.file("keystore/tcandroidkey-release.jks")
            storePassword = System.getenv("TCANDROIDKEY_STORE_PASSWORD")
            keyAlias = System.getenv("TCANDROIDKEY_KEY_ALIAS") ?: "release"
            keyPassword = System.getenv("TCANDROIDKEY_KEY_PASSWORD")
                ?: System.getenv("TCANDROIDKEY_STORE_PASSWORD")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            vcsInfo {
                include = false
            }
            val release = signingConfigs.getByName("release")
            if (release.storeFile?.exists() == true && !release.storePassword.isNullOrBlank()) {
                signingConfig = release
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    testOptions {
        unitTests {
            isReturnDefaultValues = true
        }
    }
}

dependencies {
    implementation(project(":fido-core"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.navigation.compose)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.material.icons.core)
    implementation(libs.androidx.material.icons.extended)

    testImplementation(libs.junit)

    debugImplementation(libs.androidx.ui.tooling)
}

// 利用規約・セキュリティポリシーは、リポジトリの Markdown (docs/TERMS*.md, SECURITY.md, docs/SECURITY-ja.md) を
// 唯一の原本とし、ビルド時に assets/legal/ へコピーしてアプリ内で表示する (本文をコードに二重に持たない)。
abstract class CopyLegalDocumentsTask : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NAME_ONLY)
    abstract val documents: ConfigurableFileCollection

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun copy() {
        val target = outputDir.get().asFile.resolve("legal")
        target.deleteRecursively()
        target.mkdirs()
        documents.files.forEach { it.copyTo(target.resolve(it.name), overwrite = true) }
    }
}

val copyLegalDocuments = tasks.register<CopyLegalDocumentsTask>("copyLegalDocuments") {
    documents.from(
        rootProject.file("docs/TERMS.md"),
        rootProject.file("docs/TERMS-ja.md"),
        rootProject.file("SECURITY.md"),
        rootProject.file("docs/SECURITY-ja.md")
    )
}

androidComponents {
    onVariants { variant ->
        variant.sources.assets?.addGeneratedSourceDirectory(copyLegalDocuments, CopyLegalDocumentsTask::outputDir)
    }
}
