interface BaseModel {
    fun build(): Map<String, Any>
}

fun BaseModel.build(): Map<String, Any> {
    throw NotImplementedError("Not Implemented!")
}
