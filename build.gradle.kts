// トップレベルビルドファイル: 全サブプロジェクトで共通の設定オプションを追加できます
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.kotlin.jvm) apply false
}
