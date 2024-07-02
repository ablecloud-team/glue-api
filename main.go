package main

import (
	"Glue-API/controller"
	"Glue-API/docs"
	"Glue-API/httputil"
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

//	@securityDefinitions.apikey	ApiKeyAuth
//	@in							header
//	@name						Authorization
//	@description				Description for what is this security definition being used

func main() {
	// programmatically set swagger info

	docs.SwaggerInfo.Title = "Glue API"
	docs.SwaggerInfo.Description = "This is a GlueAPI server."
	docs.SwaggerInfo.Version = "1.0"
	//docs.SwaggerInfo.Host = ".swagger.io"
	docs.SwaggerInfo.BasePath = "/"
	docs.SwaggerInfo.Schemes = []string{"https", "http"}

	httputil.Certify("cert.pem")

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	controller.LogSetting()
	r := gin.Default()
	r.ForwardedByClientIP = true
	r.SetTrustedProxies(nil)
	c := controller.NewController()
	v1 := r.Group("/api/v1")
	{
		glue := v1.Group("/glue")
		{
			glue.GET("", c.GlueStatus)

			glue.GET("/hosts", c.HostList)

			glue.GET("/version", c.GlueVersion)
		}
		pool := v1.Group("/pool")
		{
			pool.GET("", c.ListPools)

			pool.DELETE("/:pool_name", c.PoolDelete)
			pool.OPTIONS("/:pool_name", c.GlueOption)
		}
		image := v1.Group("/image")
		{
			image.GET("", c.ListAndInfoImage)
			image.POST("", c.CreateImage)
			image.DELETE("", c.DeleteImage)
			image.OPTIONS("", c.GlueOption)
		}
		service := v1.Group("/service")
		{
			service.GET("", c.ServiceLs)

			service.POST("/:service_name", c.ServiceControl)
			service.DELETE("/:service_name", c.ServiceDelete)
			service.OPTIONS("/:service_name", c.GlueOption)
		}
		fs := v1.Group("/gluefs")
		{
			fs.GET("", c.FsStatus)
			fs.PUT("", c.FsUpdate)
			fs.OPTIONS("", c.FsOption)

			fs.POST("/:fs_name", c.FsCreate)
			fs.DELETE("/:fs_name", c.FsDelete)
			fs.OPTIONS("/:fs_name", c.FsOption)

			fs.GET("/info/:fs_name", c.FsGetInfo)

			subvolume := fs.Group("/subvolume")
			{
				// subvolume.GET("", c.SubVolumeList)
				// subvolume.POST("", c.SubVolumeCreate)
				// subvolume.DELETE("", c.SubVolumeDelete)
				// subvolume.PUT("", c.SubVolumeResize)
				// subvolume.OPTIONS("", c.SubVolumeOption)

				group := subvolume.Group("/group")
				{
					group.GET("", c.SubVolumeGroupList)
					group.POST("", c.SubVolumeGroupCreate)
					group.DELETE("", c.SubVolumeGroupDelete)
					group.PUT("", c.SubVolumeGroupResize)
					group.OPTIONS("", c.SubVolumeGroupOption)

					// group.DELETE("/snapshot", c.SubVolumeGroupSnapDelete
				}
				// snapshot := subvolume.Group("/snapshot")
				// {
				// 	snapshot.GET("", c.SubVolumeSnapList)
				// 	snapshot.POST("", c.SubVolumeSnapCreate)
				// 	snapshot.DELETE("", c.SubVolumeSnapDelete)
				// 	snapshot.OPTIONS("", c.SubVolumeOption)
				// }
			}
		}
		v1.POST("/ingress", c.IngressCreate)
		v1.PUT("/ingress", c.IngressUpdate)
		v1.OPTIONS("/ingress", c.NfsOption)

		nfs := v1.Group("/nfs")
		{
			nfs.GET("", c.NfsClusterList)

			nfs.POST("/:cluster_id/:port", c.NfsClusterCreate)
			nfs.PUT("/:cluster_id/:port", c.NfsClusterUpdate)
			nfs.OPTIONS("/:cluster_id/:port", c.NfsOption)

			nfs.DELETE("/:cluster_id", c.NfsClusterDelete)
			nfs.OPTIONS("/:cluster_id", c.NfsOption)

			nfs.POST("/ingress", c.IngressCreate)
			nfs.PUT("/ingress", c.IngressUpdate)
			nfs.OPTIONS("/ingress", c.NfsOption)

			nfs_export := nfs.Group("/export")
			{
				nfs_export.GET("", c.NfsExportDetailed)

				nfs_export.POST("/:cluster_id", c.NfsExportCreate)
				nfs_export.PUT("/:cluster_id", c.NfsExportUpdate)
				nfs_export.OPTIONS("/:cluster_id", c.NfsOption)

				nfs_export.DELETE("/:cluster_id/:export_id", c.NfsExportDelete)
				nfs_export.OPTIONS("/:cluster_id/:export_id", c.NfsOption)
			}
		}
		iscsi := v1.Group("/iscsi")
		{
			iscsi.POST("", c.IscsiServiceCreate)
			iscsi.PUT("", c.IscsiServiceUpdate)
			iscsi.OPTIONS("", c.IscsiOption)

			iscsi.GET("/discovery", c.IscsiGetDiscoveryAuth)
			iscsi.PUT("/discovery", c.IscsiUpdateDiscoveryAuth)
			iscsi.OPTIONS("/discovery", c.IscsiOption)

			iscsi_target := iscsi.Group("/target")
			{
				iscsi_target.GET("", c.IscsiTargetList)
				iscsi_target.DELETE("", c.IscsiTargetDelete)
				iscsi_target.POST("", c.IscsiTargetCreate)
				iscsi_target.PUT("", c.IscsiTargetUpdate)
				iscsi_target.OPTIONS("", c.IscsiOption)

				iscsi_target.DELETE("/purge", c.IscsiTargetPurge)
				iscsi_target.OPTIONS("/purge", c.IscsiOption)
			}

		}
		smb := v1.Group("/smb")
		{
			smb.GET("", c.SmbStatus)
			smb.POST("", c.SmbCreate)
			smb.DELETE("", c.SmbDelete)
			smb.OPTIONS("", c.SmbOption)

			smb_user := smb.Group("/user")
			{
				smb_user.POST("", c.SmbUserCreate)
				smb_user.PUT("", c.SmbUserUpdate)
				smb_user.DELETE("", c.SmbUserDelete)
				smb_user.OPTIONS("", c.SmbOption)
			}
		}
		rgw := v1.Group("/rgw")
		{
			rgw.GET("", c.RgwDaemon)
			rgw.POST("", c.RgwServiceCreate)
			rgw.PUT("", c.RgwServiceUpdate)
			rgw.OPTIONS("", c.RgwOption)
			rgw.POST("/quota", c.RgwQuota)

			user := rgw.Group("/user")
			{
				user.GET("", c.RgwUserList)
				user.POST("", c.RgwUserCreate)
				user.DELETE("", c.RgwUserDelete)
				user.PUT("", c.RgwUserUpdate)
				user.OPTIONS("", c.RgwOption)
			}
			bucket := rgw.Group("/bucket")
			{
				bucket.GET("", c.RgwBucketList)
				bucket.POST("", c.RgwBucketCreate)
				bucket.PUT("", c.RgwBucketUpdate)
				bucket.DELETE("", c.RgwBucketDelete)
				bucket.OPTIONS("", c.RgwOption)
			}
		}
		nvmeof := v1.Group("/nvmeof")
		{
			nvmeof.POST("", c.NvmeOfServiceCreate)

			nvmeof.POST("/image/download", c.NvmeOfImageDownload)

			nvmeof.GET("/target", c.NvmeOfTargetList)
			nvmeof.POST("/target", c.NvmeOfTargetCreate)

			subsystem := nvmeof.Group("/subsystem")
			{
				subsystem.GET("", c.NvmeOfSubSystemList)
				subsystem.POST("", c.NvmeOfSubSystemCreate)
				subsystem.DELETE("", c.NvmeOfSubSystemDelete)
				subsystem.OPTIONS("", c.NvmeOption)
			}
			namespace := nvmeof.Group("/namespace")
			{
				namespace.GET("", c.NvmeOfNameSpaceList)
				namespace.POST("", c.NvmeOfNameSpaceCreate)
				namespace.DELETE("", c.NvmeOfNameSpaceDelete)
				namespace.OPTIONS("", c.NvmeOption)
			}
		}
		mirror := v1.Group("/mirror")
		{
			mirror.GET("", c.MirrorStatus) //Get Mirroring Status
			//Todo
			mirror.POST("", c.MirrorSetup) //Setup Mirroring
			//mirror.PATCH("", c.MirrorUpdate)  //Configure Mirroring
			mirror.DELETE("", c.MirrorDelete) //Unconfigure Mirroring
			mirror.POST("/:mirrorPool", c.MirrorPoolEnable) //Enable Mirroring Cluster
			mirror.DELETE("/:mirrorPool", c.MirrorPoolDisable) //Disable Mirroring Cluster
			mirrorimage := mirror.Group("/image")
			{
				mirrorimage.GET("", c.MirrorImageList)                             //List Mirroring Images
				mirrorimage.GET("/:mirrorPool/:imageName", c.MirrorImageInfo)      //Get Image Mirroring Info
				mirrorimage.POST("/:mirrorPool/:imageName", c.MirrorImageSetup)    //Setup Image Mirroring
				mirrorimage.PATCH("/:mirrorPool/:imageName", c.MirrorImageUpdate)  //Config Image Mirroring
				mirrorimage.DELETE("/:mirrorPool/:imageName", c.MirrorImageDelete) //Unconfigure Mirroring

				mirrorimage.GET("/status/:mirrorPool/:imageName", c.MirrorImageStatus)   //Get Image Mirroring Status
				mirrorimage.POST("/promote/:mirrorPool/:imageName", c.MirrorImagePromote) //Promote Image
				mirrorimage.DELETE("/demote/:mirrorPool/:imageName", c.MirrorImageDemote) //Demote Image
			}
			//
			//
		}
		gwvm := v1.Group("/gwvm")
		{
			gwvm.GET("/:hypervisorType", c.VmState)
			gwvm.GET("/detail/:hypervisorType", c.VmDetail)
			gwvm.POST("/:hypervisorType", c.VmSetup)        //Setup Gateway VM
			gwvm.PATCH("/start/:hypervisorType", c.VmStart) //Start to Gateway VM
			gwvm.OPTIONS("/start/:hypervisorType", c.VmStartOptions)
			gwvm.PATCH("/stop/:hypervisorType", c.VmStop) //Stop to Gateway VM
			gwvm.OPTIONS("/stop/:hypervisorType", c.VmStopOptions)
			gwvm.DELETE("/delete/:hypervisorType", c.VmDelete) //Delete to Gateway VM
			gwvm.OPTIONS("/delete/:hypervisorType", c.VmDeleteOptions)
			gwvm.PATCH("/cleanup/:hypervisorType", c.VmCleanup) //Cleanup to Gateway VM
			gwvm.OPTIONS("/cleanup/:hypervisorType", c.VmCleanupOptions)
			gwvm.PATCH("/migrate/:hypervisorType", c.VmMigrate) //Migrate to Gateway VM
			gwvm.OPTIONS("/migrate/:hypervisorType", c.VmMigrateOptions)
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
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	r.RunTLS(":8080", "cert.pem", "key.pem")
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
