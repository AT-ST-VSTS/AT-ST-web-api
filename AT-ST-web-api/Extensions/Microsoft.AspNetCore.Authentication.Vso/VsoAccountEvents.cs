// // Copyright (c) .NET Foundation. All rights reserved.
// // Licensed under the Apache License, Version 2.0. See License.txt in the project root for license information.

// using System;
// using System.Threading.Tasks;
// using System.Web;
// using Microsoft.AspNetCore.Authentication.OAuth;

// namespace Microsoft.AspNetCore.Authentication.Vso
// {
//     /// <summary>
//     /// Default <see cref="VsoAccountEvents"/> implementation.
//     /// </summary>
//     public class VsoAccountEvents : OAuthEvents
//     {
//         public new Func<RedirectContext<VsoAccountOptions>, Task> OnRedirectToAuthorizationEndpoint { get; set; } = context =>
//         {
//             var uriBuilder = new UriBuilder(context.RedirectUri);
//             var query = HttpUtility.ParseQueryString(uriBuilder.Query);
//             query["response_type"] = "Assertion";
//             uriBuilder.Query = query.ToString();
//             context.Response.Redirect(uriBuilder.ToString());
//             return Task.CompletedTask;
//         };
//     }
// }
