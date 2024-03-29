package main

import (
	"Glue-API/controller"
	"Glue-API/docs"
	"log"

	"github.com/gin-gonic/gin"

	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

//	@title			Glue-API
//	@version		v1.0
//	@description	This is a GlueAPI server.
//	@termsOfService	http://swagger.io/terms/

//	@contact.name	윤여천
//	@contact.url	http://www.ablecloud.io
//	@contact.email	support@ablecloud.io

//	@license.name	Apache 2.0
//	@license.url	http://www.apache.org/licenses/LICENSE-2.0.html

//	@BasePath	/api/v1

//	@securityDefinitions.basic	BasicAuth

// @securityDefinitions.apikey	ApiKeyAuth
// @in							header
// @name						Authorization
// @description				Description for what is this security definition being used
func main() {
	// programmatically set swagger info

	docs.SwaggerInfo.Title = "Glue API"
	docs.SwaggerInfo.Description = "This is a GlueAPI server."
	docs.SwaggerInfo.Version = "1.0"
	//docs.SwaggerInfo.Host = ".swagger.io"
	docs.SwaggerInfo.BasePath = "/"
	docs.SwaggerInfo.Schemes = []string{"http", "https"}
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	r := gin.Default()
	r.ForwardedByClientIP = true
	r.SetTrustedProxies(nil)
	c := controller.NewController()

	v1 := r.Group("/api/v1")
	{
		glue := v1.Group("/glue")
		{
			glue.GET("", c.GlueStatus)
			glue.GET("/version", c.GlueVersion)
			pool := glue.Group("/pool")
			{
				pool.GET("", c.ListPools)
				pool.GET("/:pool", c.ListImages)
			}
		}
		mirror := v1.Group("/mirror")
		{
			mirror.GET("", c.MirrorStatus) //Get Mirroring Status
			//Todo
			mirror.POST("", c.MirrorSetup) //Setup Mirroring
			//mirror.PATCH("", c.MirrorUpdate)  //Configure Mirroring
			mirror.DELETE("", c.MirrorDelete) //Unconfigure Mirroring
			//
			mirrorimage := mirror.Group("/image")
			{
				mirrorimage.GET("", c.MirrorImageList)                             //List Mirroring Images
				mirrorimage.GET("/:mirrorPool/:imageName", c.MirrorImageInfo)      //Get Image Mirroring Status
				mirrorimage.POST("/:mirrorPool/:imageName", c.MirrorImageSetup)    //Setup Image Mirroring
				mirrorimage.PATCH("/:mirrorPool/:imageName", c.MirrorImageUpdate)  //Config Image Mirroring
				mirrorimage.DELETE("/:mirrorPool/:imageName", c.MirrorImageDelete) //Unconfigure Mirroring

				mirrorimage.GET("/promote/:mirrorPool/:imageName", c.MirrorImagestatus)   //Promote Image
				mirrorimage.POST("/promote/:mirrorPool/:imageName", c.MirrorImagePromote) //
				mirrorimage.DELETE("/promote/:mirrorPool/:imageName", c.MirrorImageDemote)
			}
			//
			//
		}
		gwvm := v1.Group("/gwvm")
		{
			gwvm.GET("/:hypervisorType", c.VmState)
			gwvm.POST("/:hypervisorType", c.VmSetup)           //Setup Gateway VM
			gwvm.PUT("/start/:hypervisorType", c.VmStart)      //Start to Gateway VM
			gwvm.PUT("/stop/:hypervisorType", c.VmStop)        //Stop to Gateway VM
			gwvm.DELETE("/delete/:hypervisorType", c.VmDelete) //Delete to Gateway VM
			gwvm.PUT("/cleanup/:hypervisorType", c.VmCleanup)  //Cleanup to Gateway VM
			gwvm.PUT("/migrate/:hypervisorType", c.VmMigrate)  //Migrate to Gateway VM
		}
		/*
			admin := v1.Group("/admin")
			{
				admin.Use(auth())
				admin.POST("/auth", c.Auth)
			}
		*/
		r.Any("/version", c.Version)
	}
	r.GET("/swaggers/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	r.RunTLS(":8080", "/root/ssl/server.crt", "/root/ssl/server.key")
	// r.Run(":8080")
}

/*
func auth() gin.HandlerFunc {
	return func(c *gin.Context) {
		if len(c.GetHeader("Authorization")) == 0 {
			httputil.NewError(c, http.StatusUnauthorized, errors.New("Authorization is required Header"))
			c.Abort()
		}
		c.Next()
	}
}
*/
