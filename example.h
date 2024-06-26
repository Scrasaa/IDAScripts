// Auto reconstructed from vtable block @ 0x005658F8
// from "engine.dylib", modified by Scrasa
//Don't forget to update the return type to the correct type and check if it dumped too much!
class CEngineClient 
{
public:
/*0*/ virtual void* 	GetIntersectingSurfaces(model_t const*,Vector const&,float,bool,SurfInfo *,int) = 0;
/*1*/ virtual void* 	GetLightForPoint(Vector const&,bool) = 0;
/*2*/ virtual void* 	TraceLineMaterialAndLighting(Vector const&,Vector const&,Vector&,Vector&) = 0;
/*3*/ virtual void* 	ParseFile(char const*,char *,int) = 0;
/*4*/ virtual void* 	CopyLocalFile(char const*,char const*) = 0;
/*5*/ virtual void* 	GetScreenSize(int &,int &) = 0;
/*6*/ virtual void* 	ServerCmd(char const*,bool) = 0;
/*7*/ virtual void* 	ClientCmd(char const*) = 0;
/*8*/ virtual void* 	GetPlayerInfo(int,player_info_s *) = 0;
/*9*/ virtual void* 	GetPlayerForUserID(int) = 0;
/*10*/ virtual void* 	TextMessageGet(char const*) = 0;
/*11*/ virtual void* 	Con_IsVisible(void) = 0;
/*12*/ virtual void* 	GetLocalPlayer(void) = 0;
/*13*/ virtual void* 	LoadModel(char const*,bool) = 0;
/*14*/ virtual void* 	Time(void) = 0;
/*15*/ virtual void* 	GetLastTimeStamp(void) = 0;
/*16*/ virtual void* 	GetSentence(CAudioSource *) = 0;
/*17*/ virtual void* 	GetSentenceLength(CAudioSource *) = 0;
/*18*/ virtual void* 	IsStreaming(CAudioSource *)const = 0;
/*19*/ virtual void* 	GetViewAngles(QAngle &) = 0;
/*20*/ virtual void* 	SetViewAngles(QAngle &) = 0;
/*21*/ virtual void* 	GetMaxClients(void) = 0;
/*22*/ virtual void* 	Key_LookupBinding(char const*) = 0;
/*23*/ virtual void* 	Key_BindingForKey(ButtonCode_t) = 0;
/*24*/ virtual void* 	StartKeyTrapMode(void) = 0;
/*25*/ virtual void* 	CheckDoneKeyTrapping(ButtonCode_t &) = 0;
/*26*/ virtual void* 	IsInGame(void) = 0;
/*27*/ virtual void* 	IsConnected(void) = 0;
/*28*/ virtual void* 	IsDrawingLoadingImage(void) = 0;
/*29*/ virtual void* 	Con_NPrintf(int,char const*,...) = 0;
/*30*/ virtual void* 	Con_NXPrintf(con_nprint_s const*,char const*,...) = 0;
/*31*/ virtual void* 	IsBoxVisible(Vector const&,Vector const&) = 0;
/*32*/ virtual void* 	IsBoxInViewCluster(Vector const&,Vector const&) = 0;
/*33*/ virtual void* 	CullBox(Vector const&,Vector const&) = 0;
/*34*/ virtual void* 	Sound_ExtraUpdate(void) = 0;
/*35*/ virtual void* 	GetGameDirectory(void) = 0;
/*36*/ virtual void* 	WorldToScreenMatrix(void) = 0;
/*37*/ virtual void* 	WorldToViewMatrix(void) = 0;
/*38*/ virtual void* 	GameLumpVersion(int)const = 0;
/*39*/ virtual void* 	GameLumpSize(int)const = 0;
/*40*/ virtual void* 	LoadGameLump(int,void *,int) = 0;
/*41*/ virtual void* 	LevelLeafCount(void)const = 0;
/*42*/ virtual void* 	GetBSPTreeQuery(void) = 0;
/*43*/ virtual void* 	LinearToGamma(float *,float *) = 0;
/*44*/ virtual void* 	LightStyleValue(int) = 0;
/*45*/ virtual void* 	ComputeDynamicLighting(Vector const&,Vector const*,Vector&) = 0;
/*46*/ virtual void* 	GetAmbientLightColor(Vector &) = 0;
/*47*/ virtual void* 	GetDXSupportLevel(void) = 0;
/*48*/ virtual void* 	SupportsHDR(void) = 0;
/*49*/ virtual void* 	Mat_Stub(IMaterialSystem *) = 0;
/*50*/ virtual void* 	GetChapterName(char *,int) = 0;
/*51*/ virtual void* 	GetLevelName(void) = 0;
/*52*/ virtual void* 	GetLevelVersion(void) = 0;
/*53*/ virtual void* 	GetVoiceTweakAPI(void) = 0;
/*54*/ virtual void* 	EngineStats_BeginFrame(void) = 0;
/*55*/ virtual void* 	EngineStats_EndFrame(void) = 0;
/*56*/ virtual void* 	FireEvents(void) = 0;
/*57*/ virtual void* 	GetLeavesArea(int *,int) = 0;
/*58*/ virtual void* 	DoesBoxTouchAreaFrustum(Vector const&,Vector const&,int) = 0;
/*59*/ virtual void* 	SetAudioState(AudioState_t const&) = 0;
/*60*/ virtual void* 	SentenceGroupPick(int,char *,int) = 0;
/*61*/ virtual void* 	SentenceGroupPickSequential(int,char *,int,int,int) = 0;
/*62*/ virtual void* 	SentenceIndexFromName(char const*) = 0;
/*63*/ virtual void* 	SentenceNameFromIndex(int) = 0;
/*64*/ virtual void* 	SentenceGroupIndexFromName(char const*) = 0;
/*65*/ virtual void* 	SentenceGroupNameFromIndex(int) = 0;
/*66*/ virtual void* 	SentenceLength(int) = 0;
/*67*/ virtual void* 	ComputeLighting(Vector const&,Vector const*,bool,Vector&,Vector*) = 0;
/*68*/ virtual void* 	ActivateOccluder(int,bool) = 0;
/*69*/ virtual void* 	IsOccluded(Vector const&,Vector const&) = 0;
/*70*/ virtual void* 	SaveAllocMemory(unsigned long,unsigned long) = 0;
/*71*/ virtual void* 	SaveFreeMemory(void *) = 0;
/*72*/ virtual void* 	GetNetChannelInfo(void) = 0;
/*73*/ virtual void* 	DebugDrawPhysCollide(CPhysCollide const*,IMaterial *,matrix3x4_t &,color32_s const&) = 0;
/*74*/ virtual void* 	CheckPoint(char const*) = 0;
/*75*/ virtual void* 	DrawPortals(void) = 0;
/*76*/ virtual void* 	IsPlayingDemo(void) = 0;
/*77*/ virtual void* 	IsRecordingDemo(void) = 0;
/*78*/ virtual void* 	IsPlayingTimeDemo(void) = 0;
/*79*/ virtual void* 	GetDemoRecordingTick(void) = 0;
/*80*/ virtual void* 	GetDemoPlaybackTick(void) = 0;
/*81*/ virtual void* 	GetDemoPlaybackStartTick(void) = 0;
/*82*/ virtual void* 	GetDemoPlaybackTimeScale(void) = 0;
/*83*/ virtual void* 	GetDemoPlaybackTotalTicks(void) = 0;
/*84*/ virtual void* 	IsPaused(void) = 0;
/*85*/ virtual void* 	IsTakingScreenshot(void) = 0;
/*86*/ virtual void* 	IsHLTV(void) = 0;
/*87*/ virtual void* 	IsLevelMainMenuBackground(void) = 0;
/*88*/ virtual void* 	GetMainMenuBackgroundName(char *,int) = 0;
/*89*/ virtual void* 	GetVideoModes(int &,vmode_s *&) = 0;
/*90*/ virtual void* 	SetOcclusionParameters(OcclusionParams_t const&) = 0;
/*91*/ virtual void* 	GetUILanguage(char *,int) = 0;
/*92*/ virtual void* 	IsSkyboxVisibleFromPoint(Vector const&) = 0;
/*93*/ virtual void* 	GetMapEntitiesString(void) = 0;
/*94*/ virtual void* 	IsInEditMode(void) = 0;
/*95*/ virtual void* 	GetScreenAspectRatio(void) = 0;
/*96*/ virtual void* 	REMOVED_SteamRefreshLogin(char const*,bool) = 0;
/*97*/ virtual void* 	REMOVED_SteamProcessCall(bool &) = 0;
/*98*/ virtual void* 	GetEngineBuildNumber(void) = 0;
/*99*/ virtual void* 	GetProductVersionString(void) = 0;
/*100*/ virtual void* 	GrabPreColorCorrectedFrame(int,int,int,int) = 0;
/*101*/ virtual void* 	IsHammerRunning(void)const = 0;
/*102*/ virtual void* 	ExecuteClientCmd(char const*) = 0;
/*103*/ virtual void* 	MapHasHDRLighting(void) = 0;
/*104*/ virtual void* 	GetAppID(void) = 0;
/*105*/ virtual void* 	GetLightForPointFast(Vector const&,bool) = 0;
/*106*/ virtual void* 	ClientCmd_Unrestricted(char const*) = 0;
/*107*/ virtual void* 	SetRestrictServerCommands(bool) = 0;
/*108*/ virtual void* 	SetRestrictClientCommands(bool) = 0;
/*109*/ virtual void* 	SetOverlayBindProxy(int,void *) = 0;
/*110*/ virtual void* 	CopyFrameBufferToMaterial(char const*) = 0;
/*111*/ virtual void* 	ChangeTeam(char const*) = 0;
/*112*/ virtual void* 	ReadConfiguration(bool) = 0;
/*113*/ virtual void* 	SetAchievementMgr(IAchievementMgr *) = 0;
/*114*/ virtual void* 	GetAchievementMgr(void) = 0;
/*115*/ virtual void* 	MapLoadFailed(void) = 0;
/*116*/ virtual void* 	SetMapLoadFailed(bool) = 0;
/*117*/ virtual void* 	IsLowViolence(void) = 0;
/*118*/ virtual void* 	GetMostRecentSaveGame(void) = 0;
/*119*/ virtual void* 	SetMostRecentSaveGame(char const*) = 0;
/*120*/ virtual void* 	StartXboxExitingProcess(void) = 0;
/*121*/ virtual void* 	IsSaveInProgress(void) = 0;
/*122*/ virtual void* 	OnStorageDeviceAttached(void) = 0;
/*123*/ virtual void* 	OnStorageDeviceDetached(void) = 0;
/*124*/ virtual void* 	ResetDemoInterpolation(void) = 0;
/*125*/ virtual void* 	SetGamestatsData(CGamestatsData *) = 0;
/*126*/ virtual void* 	GetGamestatsData(void) = 0;
/*127*/ virtual void* 	GetMouseDelta(int &,int &,bool) = 0;
/*128*/ virtual void* 	ServerCmdKeyValues(KeyValues *) = 0;
/*129*/ virtual void* 	IsSkippingPlayback(void) = 0;
/*130*/ virtual void* 	IsLoadingDemo(void) = 0;
/*131*/ virtual void* 	IsPlayingDemoALocallyRecordedDemo(void) = 0;
/*132*/ virtual void* 	Key_LookupBindingExact(char const*) = 0;
/*133*/ virtual void* 	GMOD_SetTimeManipulator(float) = 0;
/*134*/ virtual void* 	GMOD_SendToServer(void *,unsigned int,bool) = 0;
/*135*/ virtual void* 	GMOD_PlaceDecalMaterial(IMaterial *,bool,int,IClientEntity *,Vector const&,Vector const&,color32_s const&,float,float) = 0;
/*136*/ virtual void* 	GMOD_GetSpew(char *,unsigned long) = 0;
/*137*/ virtual void* 	GMOD_SetViewEntity(unsigned int) = 0;
/*138*/ virtual void* 	GMOD_BrushMaterialOverride(IMaterial *) = 0;
/*139*/ virtual void* 	GMOD_R_RedownloadAllLightmaps(bool) = 0;
/*140*/ virtual void* 	GMOD_RawClientCmd_Unrestricted(char const*) = 0;
/*141*/ virtual void* 	GMOD_CreateDataTable(void (*)(void *,int,CGMODVariant const&)) = 0;
/*142*/ virtual void* 	GMOD_DestroyDataTable(IGMODDataTable *) = 0;
/*143*/ virtual void* 	GMOD_LoadModel(char const*) = 0;
/*144*/ virtual void* 	GMOD_DecalRemoveEntity(int) = 0;
/*145*/ virtual void* 	GMOD_TranslateAlias(char const*) = 0;
/*146*/ virtual void* 	GMOD_R_StudioInitLightingCache(void) = 0;
/*147*/ virtual void* 	PrecacheSentenceFile(char const*) = 0;
/*148*/ virtual void* 	GetPlayerVoiceVolume(unsigned long long) = 0;
/*149*/ virtual void* 	SetPlayerVoiceVolume(unsigned long long,float) = 0;
/*150*/ virtual void* 	NET_IsHostLocal(char const*) = 0;
/*151*/ virtual void* 	IsDedicatedServer(void) = 0;
/*152*/ virtual void* 	GetProtocolVersion(void) = 0;
/*153*/ virtual void* 	IsWindowedMode(void) = 0;
/*154*/ virtual void* 	FlashWindow(void) = 0;
/*155*/ virtual void* 	GetClientVersion(void)const = 0;
/*156*/ virtual void* 	IsActiveApp(void) = 0;
/*157*/ virtual void* 	DisconnectInternal(void) = 0;
/*158*/ virtual void* 	IsInCommentaryMode(void) = 0;
};
